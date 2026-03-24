from __future__ import annotations
from typing import Dict, Iterable, Optional, Tuple, Union, IO, List, Set
import base64
import datetime as dt
import re
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.extensions import SubjectKeyIdentifier
from cryptography.x509.oid import ExtensionOID
import hashlib
from typing import cast

from pydantic import BaseModel, ConfigDict

import urllib.request
import urllib.parse
from html import unescape

from importlib.resources import files

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
    status_start: Optional[dt.datetime]


def _first(txts: Iterable[str | None]) -> Optional[str]:
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


def _fetch_bytes(url: str, timeout: int = 10) -> Optional[bytes]:
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


def _extract_ca_id(tsp_elem: ET.Element) -> Optional[str]:
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
    source: Union[str, bytes, IO[str]],
) -> tuple[List[_CertRecord], Dict[str, List[str]]]:
    tree = (
        ET.parse(source)
        if not isinstance(source, bytes)
        else ET.ElementTree(ET.fromstring(source))
    )
    root = tree.getroot()
    if root is None:
        return [], {}

    records: List[_CertRecord] = []
    tsp_uris: Dict[str, List[str]] = {}

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


def _index_cert_for_ca(
    ca_id: str,
    cert: x509.Certificate,
    target_index: Dict[Tuple[str, str], x509.Certificate],
    target_bucket: Dict[str, list[x509.Certificate]],
) -> None:
    ca = ca_id.upper()
    target_bucket.setdefault(ca, []).append(cert)
    for cid in _derive_cert_ids(cert) + _ids_from_subject(cert):
        target_index[(ca, cid.upper())] = cert


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
        index_exact: Dict[Tuple[str, str], x509.Certificate],
        per_ca: Dict[str, list[x509.Certificate]],
        leaf_index: Optional[Dict[Tuple[str, str], x509.Certificate]] = None,
        per_ca_leaf: Optional[Dict[str, list[x509.Certificate]]] = None,
    ):
        self._index = index_exact  # TSL (souvent AC/intermédiaires)
        self._per_ca = per_ca
        self._leaf_index = leaf_index or {}  # feuilles { (CA, cert_id) -> cert }
        self._per_ca_leaf = per_ca_leaf or {}  # feuilles par CA

    @classmethod
    def from_tsl(
        cls,
        source: Union[str, bytes, IO[str]],
        *,
        fetch_leaves: bool = True,
        timeout: int = 10,
    ) -> "KeyResolver":
        recs, tsp_uris = _parse_tsl(source)

        # TSL: trie recent d'abord
        recs.sort(
            key=lambda r: (r.ca_id, r.status_start or dt.datetime.min), reverse=True
        )

        index_exact: Dict[Tuple[str, str], x509.Certificate] = {}
        per_ca: Dict[str, list[x509.Certificate]] = {}

        for r in recs:
            # index TSL (AC/intermédiaires)
            per_ca.setdefault(r.ca_id, []).append(r.cert)
            for cid in _derive_cert_ids(r.cert) + _ids_from_subject(r.cert):
                index_exact[(r.ca_id, cid.upper())] = r.cert

        # Feuilles (annuaire de l'AC via TSPInformationURI)
        leaf_index: Dict[Tuple[str, str], x509.Certificate] = {}
        per_ca_leaf: Dict[str, list[x509.Certificate]] = {}

        if fetch_leaves:
            for ca_id, uris in tsp_uris.items():
                for uri in uris:
                    data = _fetch_bytes(uri, timeout=timeout)
                    if not data:
                        continue
                    # 1) tenter des certs directement dans la page
                    certs = _parse_any_certs(data)
                    for c in certs:
                        try:
                            _index_cert_for_ca(ca_id, c, leaf_index, per_ca_leaf)
                        except Exception:
                            pass
                    # 2) si HTML, suivre les liens .cer/.crt/.der/.pem
                    if b"<html" in data.lower():
                        for link in _extract_links(data, uri):
                            blob = _fetch_bytes(link, timeout=timeout)
                            if not blob:
                                continue
                            for c in _parse_any_certs(blob):
                                try:
                                    _index_cert_for_ca(
                                        ca_id, c, leaf_index, per_ca_leaf
                                    )
                                except Exception:
                                    pass

        return cls(
            index_exact=index_exact,
            per_ca=per_ca,
            leaf_index=leaf_index,
            per_ca_leaf=per_ca_leaf,
        )

    def resolve(self, ca_id: str, cert_id: str):
        """Retourne la *clé publique* pour (CA, cert_id), en préférant une feuille EC si dispo."""
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
        possibles: Set[str] = set()
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
    def available_cert_ids(self, ca_id: str) -> Set[str]:
        """Liste les cert_id candidats connus pour un CA (d’après la TSL)."""
        out: Set[str] = set()
        for c in self._per_ca.get(ca_id.upper(), []):
            out.update(_derive_cert_ids(c))
        return out


local_key_resolver = KeyResolver.from_tsl(
    files("fr_2ddoc_parser.crypto.keys").joinpath("tsl_signed.xml").read_bytes(),
    fetch_leaves=True,
    timeout=10,
)
