from __future__ import annotations

import base64
import datetime as dt
import logging
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from html import unescape
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from pydantic import BaseModel, ConfigDict

from fr_2ddoc_parser.crypto.helper import _scan_der_certs
from fr_2ddoc_parser.crypto.trust_validator import (
    TslMetadata,
    _get_extension,
    check_certificate_revocation,
    validate_certificate_dates,
    validate_crl_against_ca,
    validate_leaf_against_ca,
    verify_tsl_xml_signature,
)
from fr_2ddoc_parser.exception.exceptions import (
    ResolverUnavailableError,
    TrustListExpiredError,
    TrustSignatureError,
    UnknownCAError,
    UnknownCertificateError,
    UntrustedCertificateError,
)
from fr_2ddoc_parser.model.models import TrustListFreshness

if TYPE_CHECKING:
    local_key_resolver: KeyResolver

logger = logging.getLogger(__name__)

ENV_TRUST_STORE_DIR = "FR_2DDOC_TRUST_STORE_DIR"
DEFAULT_TSL_URL = "https://pub.ants.gouv.fr/2D-DOC/V1/PRD/01_TSL/tsl_signed.xml"

# Namespace map (TSL ETSI)
NS = {
    "tsl": "http://uri.etsi.org/02231/v2#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xades": "http://uri.etsi.org/01903/v1.3.2#",
}

# Statut accepté (service actif / en-conformité)
SVCSTATUS_INACCORD = "http://uri.etsi.org/TrstSvc/Svcstatus/inaccord"

_FORBIDDEN_XML_DECL_RE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)

PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.+?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)
HREF_RE = re.compile(rb'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


class _CertRecord(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    ca_id: str  # "FR01", "FR03", …
    pem_der: bytes  # DER du X.509 publié dans la TSL
    cert: x509.Certificate
    status_start: dt.datetime | None


@dataclass(frozen=True)
class VerifiedCertificateContext:
    """Contexte complet d'un certificat feuille validé jusqu'à la TSL."""

    ca_id: str
    cert_id: str
    leaf_cert: x509.Certificate
    ca_cert: x509.Certificate
    tsl_sequence_number: int | None
    tsl_next_update: dt.datetime | None
    tsl_freshness: TrustListFreshness


def _parse_any_certs(data: bytes) -> list[x509.Certificate]:
    """Retourne tous les certificats X.509 trouvés dans ``data`` (PEM, DER ou multipart)."""
    found: list[x509.Certificate] = []

    for block in PEM_RE.findall(data):
        try:
            found.append(x509.load_pem_x509_certificate(block))
        except Exception:
            pass
    if found:
        return found

    try:
        found.append(x509.load_der_x509_certificate(data))
        return found
    except Exception:
        pass

    return _scan_der_certs(data)


def _fetch_bytes(url: str, timeout: int = 10) -> bytes | None:
    """Télécharge une ressource HTTP/HTTPS avec fallback HTTP pour sp.ants.gouv.fr."""
    candidates = [url]
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https" and parsed.netloc.endswith("ants.gouv.fr"):
        candidates.append(urllib.parse.urlunparse(parsed._replace(scheme="http")))

    for candidate in candidates:
        try:
            req = urllib.request.Request(
                candidate, headers={"User-Agent": "ants-2d-doc-parser/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read()
        except Exception as exc:
            logger.debug("Échec téléchargement %s: %s", candidate, exc)
    return None


def _extract_links(html: bytes, base_url: str) -> list[str]:
    """Récupère les liens .cer/.crt/.der/.pem depuis une page HTML."""
    urls: list[str] = []
    for m in HREF_RE.finditer(html):
        href = unescape(m.group(1).decode("utf-8", "ignore"))
        href = urllib.parse.urljoin(base_url, href)
        if re.search(r"\.(cer|crt|der|pem)(\?.*)?$", href, re.IGNORECASE):
            urls.append(href)
    return urls


def _extract_ca_id(tsp_elem: ET.Element) -> str | None:
    """Récupère 'FRxx' depuis TSPTradeName (ou à défaut dans TSPName)."""
    trade_names = [
        (n.text or "").strip()
        for n in tsp_elem.findall(".//tsl:TSPTradeName/tsl:Name", NS)
    ]
    for tn in trade_names:
        if re.fullmatch(r"FR\d{2}", tn):
            return tn
    for n in tsp_elem.findall(".//tsl:TSPName/tsl:Name", NS):
        m = re.search(r"(FR\d{2})", (n.text or ""))
        if m:
            return m.group(1)
    return None


def _read_source_bytes(source: str | bytes | Path | IO[str] | IO[bytes]) -> bytes:
    if isinstance(source, bytes):
        return source
    if isinstance(source, Path):
        return source.read_bytes()
    if isinstance(source, str):
        path = Path(source)
        if path.exists():
            return path.read_bytes()
        return source.encode("utf-8")
    data = source.read()
    return data.encode("utf-8") if isinstance(data, str) else data


def _parse_iso_dt(raw: str | None) -> dt.datetime | None:
    if not raw:
        return None
    txt = raw.strip()
    if not txt:
        return None
    try:
        return dt.datetime.fromisoformat(txt.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_tsl_bytes(
    xml_bytes: bytes,
) -> tuple[list[_CertRecord], dict[str, list[str]], TslMetadata]:
    if not xml_bytes or _FORBIDDEN_XML_DECL_RE.search(xml_bytes):
        raise TrustSignatureError(
            "Document XML TSL vide ou contenant une déclaration DOCTYPE/ENTITY interdite."
        )

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ResolverUnavailableError(f"XML TSL invalide: {exc}") from exc

    seq_txt = root.findtext(".//tsl:TSLSequenceNumber", default="", namespaces=NS)
    seq_num: int | None = None
    if seq_txt.strip().isdigit():
        seq_num = int(seq_txt.strip())

    issue_dt = _parse_iso_dt(
        root.findtext(".//tsl:ListIssueDateTime", default="", namespaces=NS)
    )
    next_upd = _parse_iso_dt(
        root.findtext(".//tsl:NextUpdate/tsl:dateTime", default="", namespaces=NS)
    )
    metadata = TslMetadata(
        sequence_number=seq_num,
        issue_date=issue_dt,
        next_update=next_upd,
        signer_cn=None,
    )

    records: list[_CertRecord] = []
    tsp_uris: dict[str, list[str]] = {}

    for tsp in root.findall(".//tsl:TrustServiceProvider", NS):
        ca_id = _extract_ca_id(tsp)
        if not ca_id:
            continue

        uris: list[str] = []
        for u in tsp.findall(".//tsl:TSPInformationURI/tsl:URI", NS):
            if u.text:
                uris.append(u.text.strip())
        for u in tsp.findall(".//tsl:TSPInformation/tsl:TSPInformationURI/tsl:URI", NS):
            if u.text:
                uris.append(u.text.strip())
        if uris:
            tsp_uris[ca_id] = list(dict.fromkeys(uris))

        for svc in tsp.findall(".//tsl:TSPService", NS):
            svc_status = (
                svc.findtext(".//tsl:ServiceStatus", default="", namespaces=NS) or ""
            ).strip()
            if svc_status != SVCSTATUS_INACCORD:
                continue

            status_start = _parse_iso_dt(
                svc.findtext(".//tsl:StatusStartingTime", default="", namespaces=NS)
            )

            for cert_b64_elem in svc.findall(
                ".//tsl:ServiceDigitalIdentity//tsl:X509Certificate", NS
            ):
                b64 = (cert_b64_elem.text or "").strip()
                if not b64:
                    continue
                try:
                    der = base64.b64decode(b64, validate=True)
                    cert = x509.load_der_x509_certificate(der)
                except Exception:
                    continue
                records.append(
                    _CertRecord(
                        ca_id=ca_id.upper(),
                        pem_der=der,
                        cert=cert,
                        status_start=status_start,
                    )
                )

    return records, tsp_uris, metadata


def _load_root_ca_from_store(store_dir: Path | Traversable) -> x509.Certificate:
    try:
        root_file = store_dir.joinpath("ants_tsl_root_ca.pem")
        pem_bytes = root_file.read_bytes()
    except Exception as exc:
        raise ResolverUnavailableError(
            f"Ancre de confiance ANTS (ants_tsl_root_ca.pem) introuvable: {exc}"
        ) from exc

    try:
        return x509.load_pem_x509_certificate(pem_bytes)
    except Exception as exc:
        raise ResolverUnavailableError(
            f"Impossible de charger ants_tsl_root_ca.pem: {exc}"
        ) from exc


def _load_packaged_root_ca() -> x509.Certificate:
    return _load_root_ca_from_store(files("fr_2ddoc_parser.crypto.keys"))


def _load_crl_bytes(data: bytes) -> x509.CertificateRevocationList:
    try:
        return x509.load_der_x509_crl(data)
    except Exception:
        return x509.load_pem_x509_crl(data)


def extract_crl_urls_from_certs(certs: Sequence[x509.Certificate]) -> list[str]:
    """Extrait les URLs de CRL (HTTP/HTTPS) depuis les extensions CDP des certificats."""
    urls: list[str] = []
    for cert in certs:
        cdp_ext = _get_extension(cert, x509.CRLDistributionPoints)
        if cdp_ext is None:
            continue
        for dp in cdp_ext:
            if not dp.full_name:
                continue
            for name in dp.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    val = name.value.strip()
                    if val.startswith(("http://", "https://")):
                        urls.append(val)
    return list(dict.fromkeys(urls))


class KeyResolver:
    """Résout et valide une clé publique de vérification 2D-Doc depuis la TSL ANTS.

    Aucun fallback silencieux n'est autorisé : ``(ca_id, cert_id)`` doit correspondre
    à un certificat feuille validé cryptographiquement contre son AC de la TSL.
    """

    def __init__(
        self,
        ca_records: Mapping[str, Sequence[_CertRecord]] | None = None,
        leaf_index: Mapping[tuple[str, str], x509.Certificate] | None = None,
        crls_by_ca: Mapping[str, Sequence[x509.CertificateRevocationList]]
        | None = None,
        tsl_metadata: TslMetadata | None = None,
    ) -> None:
        self._ca_records: dict[str, list[_CertRecord]] = {
            ca.upper(): list(recs) for ca, recs in (ca_records or {}).items()
        }
        self._leaf_index: dict[tuple[str, str], x509.Certificate] = {
            (ca.upper(), cid.upper()): cert
            for (ca, cid), cert in (leaf_index or {}).items()
        }
        self._crls_by_ca: dict[str, list[x509.CertificateRevocationList]] = {
            ca.upper(): list(crls) for ca, crls in (crls_by_ca or {}).items()
        }
        self._tsl_metadata = tsl_metadata

    @property
    def tsl_sequence_number(self) -> int | None:
        return self._tsl_metadata.sequence_number if self._tsl_metadata else None

    @property
    def tsl_issue_date(self) -> dt.datetime | None:
        return self._tsl_metadata.issue_date if self._tsl_metadata else None

    @property
    def tsl_next_update(self) -> dt.datetime | None:
        return self._tsl_metadata.next_update if self._tsl_metadata else None

    @property
    def ca_ids(self) -> set[str]:
        return set(self._ca_records.keys())

    def get_tsl_freshness(
        self, *, evaluation_date: dt.date | None = None
    ) -> TrustListFreshness:
        """Évalue la fraîcheur de la TSL vis-à-vis de ``tsl:NextUpdate``."""
        next_upd = self.tsl_next_update
        if next_upd is None:
            return TrustListFreshness.UNKNOWN
        if evaluation_date is not None:
            return (
                TrustListFreshness.STALE
                if evaluation_date > next_upd.date()
                else TrustListFreshness.FRESH
            )
        now_utc = dt.datetime.now(dt.timezone.utc)
        aware_next = (
            next_upd
            if next_upd.tzinfo is not None
            else next_upd.replace(tzinfo=dt.timezone.utc)
        )
        return (
            TrustListFreshness.STALE
            if now_utc > aware_next
            else TrustListFreshness.FRESH
        )

    def _match_ca_for_leaf(
        self,
        ca_id: str,
        leaf_cert: x509.Certificate,
        *,
        expected_cert_id: str | None = None,
    ) -> tuple[_CertRecord, str]:
        ca = ca_id.upper()
        records = self._ca_records.get(ca)
        if not records:
            raise UnknownCAError(f"Autorité de Certification inconnue: {ca_id}")

        last_err: UntrustedCertificateError | None = None
        for rec in records:
            try:
                cid = validate_leaf_against_ca(
                    leaf_cert, rec.cert, expected_cert_id=expected_cert_id
                )
                return rec, cid
            except UntrustedCertificateError as exc:
                last_err = exc
        raise last_err or UntrustedCertificateError(
            f"Le certificat feuille n'est approuvé par aucune AC pour {ca_id}."
        )

    def add_leaf(self, ca_id: str, leaf_cert: x509.Certificate) -> str:
        """Valide puis indexe un certificat feuille pour une AC présente dans la TSL."""
        ca = ca_id.upper()
        _, cert_id = self._match_ca_for_leaf(ca, leaf_cert)
        self._leaf_index[(ca, cert_id)] = leaf_cert
        return cert_id

    def add_crl(self, ca_id: str, crl: x509.CertificateRevocationList) -> None:
        """Valide cryptographiquement puis associe une CRL à son AC."""
        ca = ca_id.upper()
        records = self._ca_records.get(ca)
        if not records:
            raise UnknownCAError(
                f"Autorité de Certification inconnue pour CRL: {ca_id}"
            )

        last_err: TrustSignatureError | None = None
        for rec in records:
            try:
                validate_crl_against_ca(crl, rec.cert)
                self._crls_by_ca.setdefault(ca, []).append(crl)
                return
            except TrustSignatureError as exc:
                last_err = exc
        raise last_err or TrustSignatureError(
            f"CRL invalide ou non signée par l'AC {ca_id}."
        )

    @classmethod
    def from_tsl(
        cls,
        source: str | bytes | Path | IO[str] | IO[bytes],
        *,
        fetch_leaves: bool = False,
        timeout: int = 10,
        root_ca_cert: x509.Certificate | None = None,
        verify_tsl_signature: bool = True,
        leaf_certs_by_ca: Mapping[str, Sequence[x509.Certificate]] | None = None,
        crls_by_ca: Mapping[str, Sequence[x509.CertificateRevocationList]]
        | None = None,
    ) -> KeyResolver:
        """Construit un ``KeyResolver`` à partir d'une TSL XML.

        Par défaut, vérifie la signature XML-DSig contre l'ancre ANTS et
        n'effectue aucun appel réseau (``fetch_leaves=False``).
        """
        xml_bytes = _read_source_bytes(source)

        verified_meta: TslMetadata | None = None
        if verify_tsl_signature:
            anchor = root_ca_cert or _load_packaged_root_ca()
            verified_meta = verify_tsl_xml_signature(xml_bytes, anchor)

        recs, tsp_uris, parsed_meta = _parse_tsl_bytes(xml_bytes)
        meta = verified_meta or parsed_meta

        recs.sort(
            key=lambda r: (
                r.ca_id,
                r.status_start or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
            ),
            reverse=True,
        )

        ca_records: dict[str, list[_CertRecord]] = {}
        for rec in recs:
            ca_records.setdefault(rec.ca_id, []).append(rec)

        resolver = cls(ca_records=ca_records, tsl_metadata=meta)

        if leaf_certs_by_ca:
            for ca_id, certs in leaf_certs_by_ca.items():
                for cert in certs:
                    resolver.add_leaf(ca_id, cert)

        if crls_by_ca:
            for ca_id, crls in crls_by_ca.items():
                for crl in crls:
                    resolver.add_crl(ca_id, crl)

        if fetch_leaves:
            for ca_id, uris in tsp_uris.items():
                downloaded: list[x509.Certificate] = []
                for uri in uris:
                    data = _fetch_bytes(uri, timeout=timeout)
                    if not data:
                        continue
                    downloaded.extend(_parse_any_certs(data))
                    if b"<html" in data.lower():
                        for link in _extract_links(data, uri):
                            blob = _fetch_bytes(link, timeout=timeout)
                            if blob:
                                downloaded.extend(_parse_any_certs(blob))

                seen_serials: set[int] = set()
                for cert in downloaded:
                    if cert.serial_number in seen_serials:
                        continue
                    seen_serials.add(cert.serial_number)
                    try:
                        resolver.add_leaf(ca_id, cert)
                    except UntrustedCertificateError as exc:
                        logger.debug(
                            "Certificat ignoré pour %s (chaîne/contraintes invalides): %s",
                            ca_id,
                            exc,
                        )

        return resolver

    @classmethod
    def from_trust_store(
        cls,
        store_dir: Path | Traversable | None = None,
        *,
        root_ca_cert: x509.Certificate | None = None,
    ) -> KeyResolver:
        """Charge le snapshot de confiance complet hors-ligne (TSL + feuilles + CRLs)."""
        resolved_dir: Path | Traversable
        if store_dir is not None:
            resolved_dir = store_dir
        else:
            env_dir = os.environ.get(ENV_TRUST_STORE_DIR)
            if env_dir:
                env_path = Path(env_dir)
                if not env_path.is_dir():
                    raise ResolverUnavailableError(
                        f"Répertoire {ENV_TRUST_STORE_DIR} introuvable: {env_dir}"
                    )
                resolved_dir = env_path
            else:
                resolved_dir = files("fr_2ddoc_parser.crypto.keys")

        anchor = root_ca_cert or _load_root_ca_from_store(resolved_dir)

        try:
            tsl_bytes = resolved_dir.joinpath("tsl_signed.xml").read_bytes()
        except Exception as exc:
            raise ResolverUnavailableError(
                f"Impossible de lire tsl_signed.xml dans le magasin de confiance: {exc}"
            ) from exc

        resolver = cls.from_tsl(
            tsl_bytes,
            fetch_leaves=False,
            root_ca_cert=anchor,
            verify_tsl_signature=True,
        )

        # 1) Chargement des feuilles depuis trusted_leaves/<CA_ID>.pem
        loaded_leaf_count = 0
        try:
            leaves_dir = resolved_dir.joinpath("trusted_leaves")
            has_leaves_dir = leaves_dir.is_dir()
        except Exception:
            leaves_dir = None
            has_leaves_dir = False

        if has_leaves_dir and leaves_dir is not None:
            pem_files = sorted(
                (item for item in leaves_dir.iterdir() if item.name.endswith(".pem")),
                key=lambda p: p.name,
            )
            for pem_item in pem_files:
                ca_id = pem_item.name[:-4].upper()
                try:
                    pem_bytes = pem_item.read_bytes()
                except Exception as exc:
                    raise ResolverUnavailableError(
                        f"Erreur de lecture du bundle feuille {pem_item.name}: {exc}"
                    ) from exc
                certs = _parse_any_certs(pem_bytes)
                for cert in certs:
                    resolver.add_leaf(ca_id, cert)
                    loaded_leaf_count += 1

        # 2) Support optionnel d'un fichier unique trusted_leaves.pem
        try:
            single_bundle = resolved_dir.joinpath("trusted_leaves.pem")
            has_single = single_bundle.is_file()
        except Exception:
            single_bundle = None
            has_single = False

        if has_single and single_bundle is not None:
            try:
                bundle_certs = _parse_any_certs(single_bundle.read_bytes())
            except Exception as exc:
                raise ResolverUnavailableError(
                    f"Erreur de lecture de trusted_leaves.pem: {exc}"
                ) from exc
            for cert in bundle_certs:
                matched = False
                for ca_id in sorted(resolver.ca_ids):
                    try:
                        resolver.add_leaf(ca_id, cert)
                        loaded_leaf_count += 1
                        matched = True
                        break
                    except UntrustedCertificateError:
                        continue
                if not matched:
                    raise UntrustedCertificateError(
                        "Un certificat de trusted_leaves.pem n'est émis par aucune AC de la TSL."
                    )

        if loaded_leaf_count == 0:
            raise ResolverUnavailableError(
                "Aucun certificat feuille de confiance trouvé dans le magasin."
            )

        # 3) Chargement et vérification des CRLs signées crls/<CA_ID>.crl
        try:
            crls_dir = resolved_dir.joinpath("crls")
            has_crls_dir = crls_dir.is_dir()
        except Exception:
            crls_dir = None
            has_crls_dir = False

        if has_crls_dir and crls_dir is not None:
            crl_files = sorted(
                (item for item in crls_dir.iterdir() if item.name.endswith(".crl")),
                key=lambda p: p.name,
            )
            for crl_item in crl_files:
                ca_id = crl_item.name[:-4].upper()
                try:
                    crl_bytes = crl_item.read_bytes()
                    crl = _load_crl_bytes(crl_bytes)
                except Exception as exc:
                    raise ResolverUnavailableError(
                        f"CRL corrompue pour {ca_id} ({crl_item.name}): {exc}"
                    ) from exc
                resolver.add_crl(ca_id, crl)

        return resolver

    @classmethod
    def from_network(
        cls,
        tsl_url: str = DEFAULT_TSL_URL,
        *,
        root_ca_cert: x509.Certificate | None = None,
        timeout: int = 15,
    ) -> KeyResolver:
        """Télécharge explicitement la TSL, les feuilles et les CRLs avec vérification PKI."""
        anchor = root_ca_cert or _load_packaged_root_ca()
        tsl_bytes = _fetch_bytes(tsl_url, timeout=timeout)
        if not tsl_bytes:
            raise ResolverUnavailableError(
                f"Impossible de télécharger la TSL depuis {tsl_url}."
            )

        resolver = cls.from_tsl(
            tsl_bytes,
            fetch_leaves=True,
            timeout=timeout,
            root_ca_cert=anchor,
            verify_tsl_signature=True,
        )

        # Téléchargement et validation des CRLs depuis les CDPs des feuilles validées
        leaves_by_ca: dict[str, list[x509.Certificate]] = {}
        for (ca_id, _), leaf_cert in resolver._leaf_index.items():
            leaves_by_ca.setdefault(ca_id, []).append(leaf_cert)

        for ca_id, ca_leaves in leaves_by_ca.items():
            for crl_url in extract_crl_urls_from_certs(ca_leaves):
                crl_bytes = _fetch_bytes(crl_url, timeout=timeout)
                if not crl_bytes:
                    continue
                try:
                    crl = _load_crl_bytes(crl_bytes)
                    resolver.add_crl(ca_id, crl)
                    break
                except (TrustSignatureError, ValueError) as exc:
                    logger.warning("CRL ignorée (%s / %s): %s", ca_id, crl_url, exc)

        return resolver

    def resolve(self, ca_id: str, cert_id: str) -> CertificatePublicKeyTypes:
        """Retourne la clé publique validée pour ``(ca_id, cert_id)``.

        Aucun fallback sur certificat unique n'est effectué.
        """
        ca = ca_id.upper()
        cid = (cert_id or "").upper()

        if ca not in self._ca_records:
            raise UnknownCAError(f"AC inconnue dans la TSL: {ca_id}")

        leaf_cert = self._leaf_index.get((ca, cid))
        if leaf_cert is None:
            raise UnknownCertificateError(
                f"Certificat introuvable pour AC={ca_id} cert_id={cert_id}"
            )

        self._match_ca_for_leaf(ca, leaf_cert, expected_cert_id=cid)
        return leaf_cert.public_key()

    def resolve_for_verification(
        self,
        ca_id: str,
        cert_id: str,
        *,
        reference_date: dt.date | None,
        evaluation_date: dt.date,
        tsl_eval_date: dt.date | None = None,
        strict_tsl_freshness: bool = True,
    ) -> VerifiedCertificateContext:
        """Exécute la chaîne complète de résolution et validation PKI pour un 2D-DOC."""
        freshness = self.get_tsl_freshness(evaluation_date=tsl_eval_date)
        if strict_tsl_freshness and freshness == TrustListFreshness.STALE:
            raise TrustListExpiredError(
                f"TSL périmée (NextUpdate={self.tsl_next_update})."
            )

        ca = ca_id.upper()
        cid = (cert_id or "").upper()

        if ca not in self._ca_records:
            raise UnknownCAError(f"AC inconnue dans la TSL: {ca_id}")

        leaf_cert = self._leaf_index.get((ca, cid))
        if leaf_cert is None:
            raise UnknownCertificateError(
                f"Certificat introuvable pour AC={ca_id} cert_id={cert_id}"
            )

        matched_ca, _ = self._match_ca_for_leaf(ca, leaf_cert, expected_cert_id=cid)

        # Contrôle CRL (révocation)
        check_certificate_revocation(
            leaf_cert, self._crls_by_ca.get(ca, ()), reference_date
        )

        # Contrôle validité temporelle à la date de signature/émission (ou évaluation si FFFF)
        validate_certificate_dates(
            leaf_cert,
            matched_ca.cert,
            reference_date=reference_date,
            evaluation_date=evaluation_date,
            ca_status_start=matched_ca.status_start,
        )

        return VerifiedCertificateContext(
            ca_id=ca,
            cert_id=cid,
            leaf_cert=leaf_cert,
            ca_cert=matched_ca.cert,
            tsl_sequence_number=self.tsl_sequence_number,
            tsl_next_update=self.tsl_next_update,
            tsl_freshness=freshness,
        )

    def available_cert_ids(self, ca_id: str) -> set[str]:
        """Liste les ``cert_id`` validés connus pour une AC."""
        ca = ca_id.upper()
        return {cid for (entry_ca, cid) in self._leaf_index if entry_ca == ca}


_RESOLVER_LOCK = threading.Lock()
_DEFAULT_RESOLVER: KeyResolver | None = None
_DEFAULT_RESOLVER_ENV_KEY: str | None = None


def reset_default_key_resolver() -> None:
    """Réinitialise le singleton paresseux (utile pour les tests ou après rechargement)."""
    global _DEFAULT_RESOLVER, _DEFAULT_RESOLVER_ENV_KEY
    with _RESOLVER_LOCK:
        _DEFAULT_RESOLVER = None
        _DEFAULT_RESOLVER_ENV_KEY = None


def get_default_key_resolver() -> KeyResolver:
    """Retourne le singleton paresseux chargé uniquement depuis le bundle local (sans réseau)."""
    global _DEFAULT_RESOLVER, _DEFAULT_RESOLVER_ENV_KEY
    current_env = os.environ.get(ENV_TRUST_STORE_DIR)
    with _RESOLVER_LOCK:
        if _DEFAULT_RESOLVER is not None and _DEFAULT_RESOLVER_ENV_KEY == current_env:
            return _DEFAULT_RESOLVER
        resolver = KeyResolver.from_trust_store()
        _DEFAULT_RESOLVER = resolver
        _DEFAULT_RESOLVER_ENV_KEY = current_env
        return resolver


def __getattr__(name: str) -> Any:
    if name == "local_key_resolver":
        return get_default_key_resolver()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
