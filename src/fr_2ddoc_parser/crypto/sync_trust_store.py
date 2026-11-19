from __future__ import annotations

import argparse
import datetime as dt
import logging
import os
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from fr_2ddoc_parser.crypto.key_resolver import (
    DEFAULT_TSL_URL,
    KeyResolver,
    _cert_fingerprint,
    _extract_links,
    _fetch_bytes,
    _load_crl_bytes,
    _parse_any_certs,
    _parse_tsl_bytes,
    extract_crl_urls_from_certs,
)
from fr_2ddoc_parser.crypto.trust_validator import (
    is_crl_applicable,
    validate_crl_against_ca,
    validate_leaf_against_ca,
    verify_tsl_xml_signature,
)
from fr_2ddoc_parser.exception.exceptions import (
    ResolverUnavailableError,
    TrustSignatureError,
    UntrustedCertificateError,
)

logger = logging.getLogger(__name__)


def _default_keys_dir() -> Path:
    return Path(__file__).resolve().parent / "keys"


def _atomic_sync_dir(src_dir: Path, dst_dir: Path) -> None:
    """Remplace atomiquement le contenu de ``dst_dir`` depuis ``src_dir`` sur le même FS."""
    if not dst_dir.exists():
        os.replace(src_dir, dst_dir)
        return

    desired_names: set[str] = set()
    for src_file in sorted(src_dir.iterdir()):
        if src_file.is_file():
            desired_names.add(src_file.name)
            os.replace(src_file, dst_dir / src_file.name)

    for existing_file in list(dst_dir.iterdir()):
        if existing_file.is_file() and existing_file.name not in desired_names:
            existing_file.unlink()


def sync_trust_store(
    output_dir: Path | None = None,
    *,
    tsl_url: str = DEFAULT_TSL_URL,
    root_ca_path: Path | None = None,
    timeout: int = 15,
    evaluation_date: dt.date | None = None,
) -> KeyResolver:
    """Télécharge, vérifie cryptographiquement et écrit le snapshot de confiance ANTS.

    Aucun fichier cible n'est modifié tant que la TSL, toutes les chaînes
    AC -> feuille et les CRLs de chaque AC retenue n'ont pas été vérifiées cryptographiquement.
    """
    target_dir = (output_dir or _default_keys_dir()).resolve()
    anchor_path = (root_ca_path or target_dir / "ants_tsl_root_ca.pem").resolve()
    if not anchor_path.is_file():
        raise ResolverUnavailableError(f"Ancre ANTS introuvable: {anchor_path}")

    anchor_pem = anchor_path.read_bytes()
    root_ca_cert = x509.load_pem_x509_certificate(anchor_pem)

    logger.info("Téléchargement de la TSL depuis %s", tsl_url)
    tsl_bytes = _fetch_bytes(tsl_url, timeout=timeout)
    if not tsl_bytes:
        raise ResolverUnavailableError(
            f"Échec du téléchargement de la TSL depuis {tsl_url}"
        )

    meta = verify_tsl_xml_signature(tsl_bytes, root_ca_cert)
    logger.info(
        "TSL authentifiée (séquence=%s, issue=%s, next_update=%s, signataire=%s)",
        meta.sequence_number,
        meta.issue_date,
        meta.next_update,
        meta.signer_cn,
    )

    recs, tsp_uris, _ = _parse_tsl_bytes(tsl_bytes)
    ca_certs_by_id: dict[str, list[x509.Certificate]] = {}
    for rec in recs:
        if rec.ca_id.upper() == "FR00":
            continue
        ca_certs_by_id.setdefault(rec.ca_id.upper(), []).append(rec.cert)

    leaves_pem_by_ca: dict[str, bytes] = {}
    crl_der_by_issuer: dict[str, tuple[str, bytes]] = {}
    total_leaves = 0

    for ca_id in sorted(ca_certs_by_id):
        ca_certs = ca_certs_by_id[ca_id]
        uris = tsp_uris.get(ca_id, [])
        raw_certs: list[x509.Certificate] = []
        for uri in uris:
            blob = _fetch_bytes(uri, timeout=timeout)
            if not blob:
                logger.warning(
                    "Impossible de récupérer l'annuaire %s pour %s", uri, ca_id
                )
                continue
            raw_certs.extend(_parse_any_certs(blob))
            if b"<html" in blob.lower():
                for link in _extract_links(blob, uri):
                    sub_blob = _fetch_bytes(link, timeout=timeout)
                    if sub_blob:
                        raw_certs.extend(_parse_any_certs(sub_blob))

        verified_leaves: dict[
            tuple[str, int], tuple[str, x509.Certificate, x509.Certificate]
        ] = {}
        for cert in raw_certs:
            for ca_cert in ca_certs:
                try:
                    cid = validate_leaf_against_ca(cert, ca_cert)
                    issuer_key = _cert_fingerprint(ca_cert)
                    verified_leaves[(issuer_key, cert.serial_number)] = (
                        cid,
                        cert,
                        ca_cert,
                    )
                    break
                except UntrustedCertificateError:
                    continue

        sorted_leaves = sorted(
            verified_leaves.values(), key=lambda item: (item[0], item[1].serial_number)
        )
        if not sorted_leaves:
            logger.warning("Aucun certificat feuille vérifié pour l'AC %s", ca_id)
            continue

        leaves_pem_by_ca[ca_id] = b"".join(
            cert.public_bytes(Encoding.PEM) for _, cert, _ in sorted_leaves
        )
        total_leaves += len(sorted_leaves)
        logger.info(
            "AC %s : %d certificat(s) feuille(s) vérifié(s)", ca_id, len(sorted_leaves)
        )

        issuer_groups: dict[str, tuple[x509.Certificate, list[x509.Certificate]]] = {}
        for _, leaf_cert, issuer_cert in sorted_leaves:
            issuer_key = _cert_fingerprint(issuer_cert)
            group = issuer_groups.setdefault(issuer_key, (issuer_cert, []))
            group[1].append(leaf_cert)

        # Une CRL courante est obligatoire pour chaque émetteur réellement retenu.
        for issuer_key, (issuer_cert, issuer_leaves) in issuer_groups.items():
            crl_urls = extract_crl_urls_from_certs(issuer_leaves)
            for crl_url in crl_urls:
                crl_bytes = _fetch_bytes(crl_url, timeout=timeout)
                if not crl_bytes:
                    continue
                try:
                    crl = _load_crl_bytes(crl_bytes)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("CRL illisible (%s / %s): %s", ca_id, crl_url, exc)
                    continue

                try:
                    validate_crl_against_ca(crl, issuer_cert)
                    if not is_crl_applicable(crl, evaluation_date):
                        logger.warning(
                            "CRL non applicable à la date courante (%s / %s)",
                            ca_id,
                            crl_url,
                        )
                        continue
                    crl_der_by_issuer[issuer_key] = (
                        ca_id,
                        crl.public_bytes(Encoding.DER),
                    )
                    logger.info(
                        "AC %s/%s : CRL vérifiée (%d révocations, %s)",
                        ca_id,
                        issuer_key[:12],
                        len(crl),
                        crl_url,
                    )
                    break
                except TrustSignatureError:
                    continue

            if issuer_key not in crl_der_by_issuer:
                raise ResolverUnavailableError(
                    f"Aucune CRL courante valide récupérée pour l'émetteur {ca_id}/{issuer_key[:12]} (abandon fail-closed)."
                )

    if total_leaves == 0:
        raise ResolverUnavailableError(
            "Aucun certificat feuille vérifié téléchargé : abandon de la synchronisation."
        )

    # Staging sur le même système de fichiers (target_dir.parent), validation puis promotion atomique
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{target_dir.name}.staging-",
        dir=target_dir.parent,
    ) as tmp_str:
        tmp_dir = Path(tmp_str)
        (tmp_dir / "ants_tsl_root_ca.pem").write_bytes(anchor_pem)
        (tmp_dir / "tsl_signed.xml").write_bytes(tsl_bytes)

        leaves_tmp = tmp_dir / "trusted_leaves"
        leaves_tmp.mkdir(parents=True, exist_ok=True)
        for ca_id, pem_bundle in leaves_pem_by_ca.items():
            (leaves_tmp / f"{ca_id}.pem").write_bytes(pem_bundle)

        crls_tmp = tmp_dir / "crls"
        crls_tmp.mkdir(parents=True, exist_ok=True)
        for issuer_key, (ca_id, der_crl) in crl_der_by_issuer.items():
            (crls_tmp / f"{ca_id}-{issuer_key}.crl").write_bytes(der_crl)

        # Validation complète du magasin stagé avant promotion
        staged = KeyResolver.from_trust_store(tmp_dir, require_crls=True)
        staged._ensure_crl_coverage(
            require_current=True, evaluation_date=evaluation_date
        )

        target_dir.mkdir(parents=True, exist_ok=True)
        _atomic_sync_dir(leaves_tmp, target_dir / "trusted_leaves")
        _atomic_sync_dir(crls_tmp, target_dir / "crls")
        os.replace(
            tmp_dir / "ants_tsl_root_ca.pem", target_dir / "ants_tsl_root_ca.pem"
        )
        os.replace(tmp_dir / "tsl_signed.xml", target_dir / "tsl_signed.xml")

    logger.info(
        "Magasin de confiance mis à jour dans %s (%d feuilles, %d CRLs)",
        target_dir,
        total_leaves,
        len(crl_der_by_issuer),
    )
    return KeyResolver.from_trust_store(target_dir, require_crls=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Synchronise et vérifie le snapshot de confiance ANTS 2D-Doc."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_default_keys_dir(),
        help="Répertoire cible du magasin de confiance.",
    )
    parser.add_argument(
        "--tsl-url",
        default=DEFAULT_TSL_URL,
        help="URL de la TSL signée ANTS.",
    )
    parser.add_argument(
        "--root-ca",
        type=Path,
        default=None,
        help="Chemin vers le certificat PEM de l'ancre ANTS.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Timeout réseau par requête en secondes.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    sync_trust_store(
        output_dir=args.output_dir,
        tsl_url=args.tsl_url,
        root_ca_path=args.root_ca,
        timeout=args.timeout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
