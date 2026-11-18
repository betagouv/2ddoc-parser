from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
import re
import sys
import threading
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from html import unescape
from importlib.resources import files
from pathlib import Path
from typing import IO, cast

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.extensions import SubjectKeyIdentifier
from cryptography.x509.oid import ExtensionOID
from pydantic import BaseModel, ConfigDict

from fr_2ddoc_parser.crypto.helper import _scan_der_certs

# Namespace map (TSL ETSI)
NS = {
    "tsl": "http://uri.etsi.org/02231/v2#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xades": "http://uri.etsi.org/01903/v1.3.2#",
}

# Statut accepté (service actif / en-conformité)
SVCSTATUS_INACCORD = "http://uri.etsi.org/TrstSvc/Svcstatus/inaccord"


class _CertRecord(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    ca_id: str  # "FR01", "FR03", …
    pem_der: bytes  # DER du X.509 publié dans la TSL
    cert: x509.Certificate
    status_start: dt.datetime | None


def _first(txts: Iterable[str | None]) -> str | None:
    for t in txts:
        if t:
            return t
    return None


def _ids_from_subject(cert: x509.Certificate) -> list[str]:
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        return []
    cn = str(cn or "")
    ids = set()
    for m in re.finditer(r"\b[A-Z0-9]{4}\b", cn.upper()):
        ids.add(m.group(0))
    return list(ids)


PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.+?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)


def _parse_any_certs(data: bytes) -> list[x509.Certificate]:
    """
    Retourne tous les x509 trouvés dans 'data':
      - PEM multiples
      - DER “propre”
      - flux 'multipart pkix-cert' ou binaire mixte → scan DER
    """
    found: list[x509.Certificate] = []

    # 1) PEM multiples
    for block in PEM_RE.findall(data):
        try:
            found.append(x509.load_pem_x509_certificate(block))
        except Exception:
            pass
    if found:
        return found

    # 2) DER unique “propre”
    try:
        found.append(x509.load_der_x509_certificate(data))
        return found
    except Exception:
        pass

    # 3) Cas “multipart pkix-cert” ou binaire bruité → scan DER
    # (heuristique: présence des marqueurs ou scan inconditionnel)
    if (b"application/pkix-cert" in data.lower()) or (b"--end" in data.lower()):
        scanned = _scan_der_certs(data)
        if scanned:
            return scanned

    # 4) Dernier recours: tenter un scan DER même sans heuristique
    scanned = _scan_der_certs(data)
    return scanned


def _fetch_bytes(url: str, timeout: int = 10) -> bytes | None:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "ants-2d-doc-parser/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None


HREF_RE = re.compile(rb'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


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
    # fallback: chercher FRxx dans le nom
    for n in tsp_elem.findall(".//tsl:TSPName/tsl:Name", NS):
        m = re.search(r"(FR\d{2})", (n.text or ""))
        if m:
            return m.group(1)
    return None


def _parse_tsl(
    source: str | bytes | IO[str],
) -> tuple[list[_CertRecord], dict[str, list[str]]]:
    tree = (
        ET.parse(source)
        if not isinstance(source, bytes)
        else ET.ElementTree(ET.fromstring(source))
    )
    root = tree.getroot()
    if root is None:
        return [], {}

    records: list[_CertRecord] = []
    tsp_uris: dict[str, list[str]] = {}

    for tsp in root.findall(".//tsl:TrustServiceProvider", NS):
        ca_id = _extract_ca_id(tsp)
        if not ca_id:
            continue

        # Récupère les TSPInformationURI (plusieurs possibles)
        uris = []
        # Variante 1 (courante)
        for u in tsp.findall(".//tsl:TSPInformationURI/tsl:URI", NS):
            if u.text:
                uris.append(u.text.strip())
        # Variante 2 (selon TSL)
        for u in tsp.findall(".//tsl:TSPInformation/tsl:TSPInformationURI/tsl:URI", NS):
            if u.text:
                uris.append(u.text.strip())
        if uris:
            tsp_uris[ca_id] = list(dict.fromkeys(uris))  # dedup

        # Services actifs
        for svc in tsp.findall(".//tsl:TSPService", NS):
            svc_status = (
                svc.findtext(".//tsl:ServiceStatus", default="", namespaces=NS) or ""
            ).strip()
            if svc_status != SVCSTATUS_INACCORD:
                continue

            start_txt = svc.findtext(
                ".//tsl:StatusStartingTime", default="", namespaces=NS
            )
            status_start = None
            if start_txt:
                try:
                    status_start = dt.datetime.fromisoformat(
                        start_txt.replace("Z", "+00:00")
                    )
                except Exception:
                    status_start = None

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
                        ca_id=ca_id, pem_der=der, cert=cert, status_start=status_start
                    )
                )

    return records, tsp_uris


def _derive_cert_ids(cert: x509.Certificate) -> list[str]:
    """
    Construit des 'cert_id' candidats à partir du X.509 pour faire la jonction
    avec le champ court du header DC04 (souvent 4 caractères).
    On génère plusieurs variantes pour être tolerant côté mapping.
    """
    ids: set[str] = set()

    # Serial → dernières n hex-digits
    serial_hex = f"{cert.serial_number:X}"
    for n in (4, 5, 6, 8):
        if len(serial_hex) >= n:
            ids.add(serial_hex[-n:].upper())

    # SKI (Subject Key Identifier) → dernières n hex-digits
    try:
        ski_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ski = cast(SubjectKeyIdentifier, ski_ext.value).digest.hex().upper()
        for n in (4, 5, 6, 8):
            if len(ski) >= n:
                ids.add(ski[-n:])
    except x509.ExtensionNotFound:
        pass

    # Empreinte SPKI (SubjectPublicKeyInfo) → premières n hex-digits (SHA-1)
    spki_der = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    spki_sha1 = hashlib.sha1(spki_der).hexdigest().upper()
    for n in (4, 6, 8):
        ids.add(spki_sha1[:n])

    return list(ids)


def _cert_fingerprint(cert: x509.Certificate) -> bytes:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).digest()


def _dedupe_certs(certs: Iterable[x509.Certificate]) -> list[x509.Certificate]:
    seen: set[bytes] = set()
    out: list[x509.Certificate] = []
    for cert in certs:
        fingerprint = _cert_fingerprint(cert)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        out.append(cert)
    return out


def _index_cert_ids(
    ca_id: str,
    cert: x509.Certificate,
    target_index: dict[tuple[str, str], x509.Certificate],
) -> None:
    ca = ca_id.upper()
    for cid in _derive_cert_ids(cert) + _ids_from_subject(cert):
        target_index[(ca, cid.upper())] = cert


def _index_cert_for_ca(
    ca_id: str,
    cert: x509.Certificate,
    target_index: dict[tuple[str, str], x509.Certificate],
    target_bucket: dict[str, list[x509.Certificate]],
) -> None:
    ca = ca_id.upper()
    target_bucket.setdefault(ca, []).append(cert)
    _index_cert_ids(ca, cert, target_index)


class KeyResolver:
    """
    Résout une clé publique à partir de la TSL ANTS (2D-Doc).

    Lookup:
      1) (ca_id, cert_id) exact si 'cert_id' matche une des stratégies dérivées.
      2) si un seul certificat pour ce CA → fallback automatique.
      3) sinon lève KeyError en listant les cert_id connus pour ce CA.

    Exemple:
        r = TslKeyResolver.from_tsl("tsl_signed.xml")
        pub = r.resolve("FR05", "ABCD")  # si 'ABCD' matche un des IDs dérivés
        # ou fallback si FR05 n'a qu'un seul cert publié.
    """

    def __init__(
        self,
        index_exact: dict[tuple[str, str], x509.Certificate],
        per_ca: dict[str, list[x509.Certificate]],
        leaf_index: dict[tuple[str, str], x509.Certificate] | None = None,
        per_ca_leaf: dict[str, list[x509.Certificate]] | None = None,
        tsp_uris: dict[str, list[str]] | None = None,
        cache_dir: str | os.PathLike[str] | None = None,
        lazy_leaves: bool = False,
        timeout: int = 10,
    ):
        self._index = index_exact  # TSL (souvent AC/intermédiaires)
        self._per_ca = per_ca
        self._leaf_index = leaf_index or {}  # feuilles { (CA, cert_id) -> cert }
        self._per_ca_leaf = per_ca_leaf or {}  # feuilles par CA
        self._tsp_uris = tsp_uris or {}  # annuaires par CA
        self._cache_dir = Path(cache_dir) if cache_dir is not None else None
        self._lazy_leaves = lazy_leaves
        self._timeout = timeout
        self._leaves_loaded: set[str] = set()
        self._lock = threading.RLock()
        self._ca_locks: dict[str, threading.Lock] = {}
        self._ca_locks_lock = threading.Lock()

    @classmethod
    def from_tsl(
        cls,
        source: str | bytes | IO[str],
        *,
        fetch_leaves: bool = True,
        lazy_leaves: bool = False,
        cache_dir: str | os.PathLike[str] | None = None,
        timeout: int = 10,
    ) -> KeyResolver:
        recs, tsp_uris = _parse_tsl(source)

        # TSL: trie recent d'abord
        recs.sort(
            key=lambda r: (r.ca_id, r.status_start or dt.datetime.min), reverse=True
        )

        index_exact: dict[tuple[str, str], x509.Certificate] = {}
        per_ca: dict[str, list[x509.Certificate]] = {}

        for r in recs:
            # index TSL (AC/intermédiaires)
            per_ca.setdefault(r.ca_id, []).append(r.cert)
            for cid in _derive_cert_ids(r.cert) + _ids_from_subject(r.cert):
                index_exact[(r.ca_id, cid.upper())] = r.cert

        resolver = cls(
            index_exact=index_exact,
            per_ca=per_ca,
            tsp_uris=tsp_uris,
            cache_dir=cache_dir,
            lazy_leaves=lazy_leaves,
            timeout=timeout,
        )

        # Charge les feuilles déjà présentes dans le cache (aucune I/O réseau).
        resolver.load_cache()

        # Téléchargement explicite (build Docker, CLI, etc.).
        if fetch_leaves:
            resolver.refresh_leaves()

        return resolver

    def _ca_lock(self, ca_id: str) -> threading.Lock:
        ca = ca_id.upper()
        with self._ca_locks_lock:
            lock = self._ca_locks.get(ca)
            if lock is None:
                lock = threading.Lock()
                self._ca_locks[ca] = lock
            return lock

    def _download_leaves_for_ca(
        self, ca_id: str
    ) -> tuple[list[x509.Certificate], bool]:
        """Télécharge les feuilles d'un CA sans verrouiller l'index partagé."""
        ca = ca_id.upper()
        certs: list[x509.Certificate] = []
        had_failure = False

        for uri in self._tsp_uris.get(ca, []):
            data = _fetch_bytes(uri, timeout=self._timeout)
            if not data:
                had_failure = True
                continue
            # 1) tenter des certs directement dans la page
            certs.extend(_parse_any_certs(data))
            # 2) si HTML, suivre les liens .cer/.crt/.der/.pem
            if b"<html" in data.lower():
                for link in _extract_links(data, uri):
                    blob = _fetch_bytes(link, timeout=self._timeout)
                    if not blob:
                        had_failure = True
                        continue
                    link_certs = _parse_any_certs(blob)
                    if not link_certs:
                        had_failure = True
                        continue
                    certs.extend(link_certs)

        return _dedupe_certs(certs), had_failure

    def _publish_leaves_for_ca(
        self,
        ca_id: str,
        new_certs: list[x509.Certificate],
        had_failure: bool,
    ) -> None:
        """Met à jour l'index partagé. Doit être appelé avec self._lock."""
        ca = ca_id.upper()
        # En cas d'échec partiel, conserve les certificats déjà en cache.
        if had_failure:
            merged = _dedupe_certs([*self._per_ca_leaf.get(ca, []), *new_certs])
        else:
            merged = new_certs

        for key in [k for k in self._leaf_index if k[0] == ca]:
            del self._leaf_index[key]
        self._per_ca_leaf[ca] = merged
        for c in merged:
            try:
                _index_cert_ids(ca, c, self._leaf_index)
            except Exception:
                pass

    def _write_cache_for_ca(self, ca_id: str, cache_dir: Path) -> None:
        certs = self._per_ca_leaf.get(ca_id.upper(), [])
        if not certs:
            return
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / f"{ca_id.upper()}.pem"
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            tmp.write_bytes(b"".join(c.public_bytes(Encoding.PEM) for c in certs))
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)

    def load_cache(self, cache_dir: str | os.PathLike[str] | None = None) -> None:
        """Charge les feuilles depuis un répertoire de cache, sans réseau."""
        target = Path(cache_dir) if cache_dir is not None else self._cache_dir
        if target is None or not target.is_dir():
            return
        with self._lock:
            for path in sorted(target.glob("*.pem")):
                ca = path.stem.upper()
                try:
                    data = path.read_bytes()
                except OSError:
                    continue
                for c in _parse_any_certs(data):
                    try:
                        _index_cert_for_ca(ca, c, self._leaf_index, self._per_ca_leaf)
                    except Exception:
                        pass
                self._per_ca_leaf[ca] = _dedupe_certs(self._per_ca_leaf.get(ca, []))
                self._leaves_loaded.add(ca)

    def refresh_leaves(
        self,
        ca_id: str | None = None,
        *,
        cache_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        """Télécharge les feuilles (tous les CA ou un seul) et met le cache à jour."""
        target = Path(cache_dir) if cache_dir is not None else self._cache_dir
        targets = [ca_id.upper()] if ca_id else list(self._tsp_uris)
        for ca in targets:
            with self._ca_lock(ca):
                new_certs, had_failure = self._download_leaves_for_ca(ca)
                with self._lock:
                    if new_certs:
                        self._publish_leaves_for_ca(ca, new_certs, had_failure)
                    if had_failure:
                        self._leaves_loaded.discard(ca)
                    elif self._per_ca_leaf.get(ca):
                        self._leaves_loaded.add(ca)
                    if target is not None:
                        self._write_cache_for_ca(ca, target)

    def _ensure_leaves(self, ca_id: str) -> None:
        ca = ca_id.upper()
        if not self._lazy_leaves:
            return
        with self._lock:
            if ca in self._leaves_loaded:
                return
        with self._ca_lock(ca):
            with self._lock:
                if ca in self._leaves_loaded:
                    return
            new_certs, had_failure = self._download_leaves_for_ca(ca)
            if not new_certs:
                return
            with self._lock:
                self._publish_leaves_for_ca(ca, new_certs, had_failure)
                if had_failure:
                    self._leaves_loaded.discard(ca)
                else:
                    self._leaves_loaded.add(ca)
                if self._cache_dir is not None:
                    self._write_cache_for_ca(ca, self._cache_dir)

    def resolve(self, ca_id: str, cert_id: str):
        """Retourne la *clé publique* pour (CA, cert_id), en préférant une feuille EC si dispo."""
        self._ensure_leaves(ca_id)
        with self._lock:
            key = self._leaf_index.get((ca_id.upper(), (cert_id or "").upper()))
            if key is not None:
                return key.public_key()

            key = self._index.get((ca_id.upper(), (cert_id or "").upper()))
            if key is not None:
                return key.public_key()

            # Fallback: unique feuille pour ce CA ?
            leafs = self._per_ca_leaf.get(ca_id.upper(), [])
            if len(leafs) == 1:
                return leafs[0].public_key()

            # Sinon, fallback TSL classique: unique cert pour ce CA ?
            certs = self._per_ca.get(ca_id.upper(), [])
            if len(certs) == 1:
                return certs[0].public_key()

            # Debug: lister IDs possibles (feuilles + TSL)
            possibles: set[str] = set()
            for c in leafs:
                possibles.update(_derive_cert_ids(c))
                possibles.update(_ids_from_subject(c))
            for c in certs:
                possibles.update(_derive_cert_ids(c))
                possibles.update(_ids_from_subject(c))

            if possibles:
                raise KeyError(
                    f"Cert public introuvable pour AC={ca_id} cert_id={cert_id}. "
                    f"IDs possibles (leaf+tsl): {', '.join(sorted(possibles))}"
                )
            raise KeyError(f"AC inconnu: {ca_id}")

    # Helpers optionnels
    def available_cert_ids(self, ca_id: str) -> set[str]:
        """Liste les cert_id candidats connus pour un CA (d’après la TSL)."""
        out: set[str] = set()
        for c in self._per_ca.get(ca_id.upper(), []):
            out.update(_derive_cert_ids(c))
        return out

    def leaf_count(self, ca_id: str | None = None) -> int:
        """Nombre de certificats feuilles actuellement chargés."""
        if ca_id is not None:
            return len(self._per_ca_leaf.get(ca_id.upper(), []))
        return sum(len(certs) for certs in self._per_ca_leaf.values())


CACHE_DIR_ENV = "FR_2DDOC_KEY_CACHE"


def _tsl_bytes() -> bytes:
    return files("fr_2ddoc_parser.crypto.keys").joinpath("tsl_signed.xml").read_bytes()


def _cache_dir_from_env() -> Path | None:
    value = os.environ.get(CACHE_DIR_ENV)
    return Path(value) if value else None


def load_key_resolver(
    *,
    fetch_leaves: bool = False,
    lazy_leaves: bool | None = None,
    cache_dir: str | os.PathLike[str] | None = None,
    timeout: int = 10,
) -> KeyResolver:
    """Construit un KeyResolver sans I/O réseau à l'import.

    - cache_dir=None : utilise la variable d'environnement FR_2DDOC_KEY_CACHE.
    - fetch_leaves=True : télécharge immédiatement les feuilles (build/CLI).
    - lazy_leaves=None (défaut) : téléchargement paresseux au premier resolve()
      uniquement si aucun cache n'est configuré. Avec un cache, aucun réseau.
    - lazy_leaves=True/False : force le comportement.
    """
    if cache_dir is None:
        cache_dir = _cache_dir_from_env()
    if lazy_leaves is None:
        lazy_leaves = cache_dir is None
    return KeyResolver.from_tsl(
        _tsl_bytes(),
        fetch_leaves=fetch_leaves,
        lazy_leaves=lazy_leaves,
        cache_dir=cache_dir,
        timeout=timeout,
    )


def refresh_keys(
    cache_dir: str | os.PathLike[str],
    *,
    timeout: int = 10,
    ca_id: str | None = None,
) -> int:
    """Télécharge les feuilles de la TSL dans `cache_dir`.

    Retourne le nombre de certificats feuilles disponibles après le refresh.
    Lève `RuntimeError` si aucun certificat n'est disponible, afin qu'un
    `python -c` dans un Dockerfile échoue au lieu de produire une image sans clés.
    """
    resolver = KeyResolver.from_tsl(
        _tsl_bytes(),
        fetch_leaves=False,
        cache_dir=cache_dir,
        timeout=timeout,
    )
    resolver.refresh_leaves(ca_id, cache_dir=cache_dir)
    if ca_id is not None:
        if resolver.leaf_count(ca_id) == 0:
            raise RuntimeError(f"Aucun certificat feuille pour {ca_id}")
    elif resolver.leaf_count() == 0:
        raise RuntimeError("Aucun certificat feuille téléchargé")
    return resolver.leaf_count()


# Aucune requête réseau à l'import : la TSL locale est parsée et le cache
# éventuel (FR_2DDOC_KEY_CACHE) est chargé. Sans cache, les feuilles du CA
# concerné sont téléchargées paresseusement au premier resolve().
local_key_resolver = load_key_resolver()


def main(argv: list[str] | None = None) -> int:
    """Télécharge les feuilles de la TSL dans un répertoire de cache.

    Exemple Dockerfile :
        RUN python -m fr_2ddoc_parser.crypto.key_resolver --cache-dir /opt/2ddoc-keys
        ENV FR_2DDOC_KEY_CACHE=/opt/2ddoc-keys
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Télécharge les certificats feuilles de la TSL 2D-Doc."
    )
    parser.add_argument(
        "--cache-dir",
        required=True,
        help="Répertoire où écrire les certificats (un fichier PEM par CA).",
    )
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument(
        "--ca",
        action="append",
        dest="cas",
        help="Limiter à un CA (ex: FR06). Option répétable.",
    )
    args = parser.parse_args(argv)

    resolver = KeyResolver.from_tsl(
        _tsl_bytes(),
        fetch_leaves=False,
        cache_dir=args.cache_dir,
        timeout=args.timeout,
    )
    if args.cas:
        for ca in args.cas:
            resolver.refresh_leaves(ca, cache_dir=args.cache_dir)
        missing = [ca for ca in args.cas if resolver.leaf_count(ca) == 0]
        if missing:
            print(
                f"Aucun certificat feuille pour : {', '.join(missing)}",
                file=sys.stderr,
            )
            return 1
    else:
        resolver.refresh_leaves(cache_dir=args.cache_dir)
        if resolver.leaf_count() == 0:
            print("Aucun certificat feuille téléchargé.", file=sys.stderr)
            return 1

    total = resolver.leaf_count()
    print(f"{total} certificat(s) feuille(s) écrit(s) dans {args.cache_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
