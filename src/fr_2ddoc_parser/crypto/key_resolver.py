from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import logging
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from html import unescape
from http.client import HTTPMessage
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from pydantic import BaseModel, ConfigDict

from fr_2ddoc_parser.crypto.helper import _scan_der_certs
from fr_2ddoc_parser.crypto.trust_validator import (
    _FORBIDDEN_XML_DECL_RE,
    TslMetadata,
    _get_extension,
    _parse_iso_datetime,
    check_certificate_revocation,
    is_crl_applicable,
    validate_certificate_dates,
    validate_crl_against_ca,
    validate_leaf_against_ca,
    verify_tsl_xml_signature,
)
from fr_2ddoc_parser.exception.exceptions import (
    CertificateRevokedError,
    CertificateValidityError,
    ResolverUnavailableError,
    TrustListExpiredError,
    TrustSignatureError,
    UnknownCAError,
    UnknownCertificateError,
    UntrustedCertificateError,
)
from fr_2ddoc_parser.model.models import CrlRefreshResult, TrustListFreshness

if TYPE_CHECKING:
    local_key_resolver: KeyResolver

logger = logging.getLogger(__name__)

ENV_TRUST_STORE_DIR = "FR_2DDOC_TRUST_STORE_DIR"
DEFAULT_TSL_URL = "https://pub.ants.gouv.fr/2D-DOC/V1/PRD/01_TSL/tsl_signed.xml"
_MAX_FETCH_BYTES = 10 * 1024 * 1024  # 10 MiB
_MAX_LINKS_PER_PAGE = 500
_CA_ID_RE = re.compile(r"^FR\d{2}$")
_CRL_FILE_STEM_RE = re.compile(r"^(FR\d{2})(?:-[0-9A-Fa-f]{64})?$")
_DEFAULT_URLOPEN = urllib.request.urlopen

# Namespace map (TSL ETSI)
NS = {
    "tsl": "http://uri.etsi.org/02231/v2#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xades": "http://uri.etsi.org/01903/v1.3.2#",
}

# Statut accepté (service actif / en-conformité)
SVCSTATUS_INACCORD = "http://uri.etsi.org/TrstSvc/Svcstatus/inaccord"

PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.+?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)
HREF_RE = re.compile(rb'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def _cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


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


@dataclass(frozen=True)
class VerifiedCandidateSet:
    """Candidats utilisables et incertitude résiduelle sur d'autres clés."""

    contexts: list[VerifiedCertificateContext]
    unavailable_detail: str | None = None


@dataclass
class _CandidateResolutionCapture:
    resolver: object
    request: tuple[
        str,
        str,
        dt.date | None,
        dt.date | None,
        dt.date | None,
        bool,
    ]
    result: VerifiedCandidateSet | None = None


_CANDIDATE_RESOLUTION_CAPTURE: ContextVar[_CandidateResolutionCapture | None] = (
    ContextVar("candidate_resolution_capture", default=None)
)


def _parse_any_certs(data: bytes) -> list[x509.Certificate]:
    """Retourne tous les certificats X.509 trouvés dans ``data`` (PEM, DER ou multipart)."""
    found: list[x509.Certificate] = []

    for block in PEM_RE.findall(data):
        try:
            found.append(x509.load_pem_x509_certificate(block))
        except Exception as exc:  # noqa: BLE001
            logger.debug("Bloc PEM invalide ignoré: %s", exc)
    if found:
        return found

    try:
        found.append(x509.load_der_x509_certificate(data))
        return found
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "Chargement DER direct impossible, bascule sur scan binaire: %s", exc
        )

    return _scan_der_certs(data)


def _is_safe_http_url(url: str) -> urllib.parse.ParseResult | None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return None

    host = parsed.hostname.strip().lower().rstrip(".")
    if not host or host in {"localhost", "ip6-localhost", "localhost.localdomain"}:
        return None
    if host.endswith((".localhost", ".local")):
        return None

    ip_candidate = host.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(ip_candidate)
    except ValueError:
        return parsed

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return None
    return parsed


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler HTTP bloquant les redirections non sûres (schémas, IP privées, downgrade HTTPS->HTTP)."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        resolved_url = urllib.parse.urljoin(req.full_url, newurl)
        target = _is_safe_http_url(resolved_url)
        if target is None:
            raise urllib.error.URLError(
                f"Redirection HTTP bloquée (URL non autorisée): {resolved_url}"
            )
        orig_scheme = urllib.parse.urlparse(req.full_url).scheme.lower()
        if orig_scheme == "https" and target.scheme.lower() != "https":
            raise urllib.error.URLError(
                f"Downgrade HTTPS -> HTTP bloqué lors d'une redirection: {resolved_url}"
            )
        return super().redirect_request(req, fp, code, msg, headers, resolved_url)


def _fetch_bytes(url: str, timeout: int = 10) -> bytes | None:
    """Télécharge une ressource HTTP/HTTPS avec fallback HTTP pour sp.ants.gouv.fr."""
    parsed = _is_safe_http_url(url)
    if parsed is None:
        logger.warning("URL rejetée (schéma ou hôte non autorisé): %s", url)
        return None

    candidates = [url]
    host = (parsed.hostname or "").lower()
    if parsed.scheme.lower() == "https" and host == "sp.ants.gouv.fr":
        candidates.append(urllib.parse.urlunparse(parsed._replace(scheme="http")))

    for candidate in candidates:
        try:
            req = urllib.request.Request(
                candidate, headers={"User-Agent": "ants-2d-doc-parser/1.0"}
            )
            if urllib.request.urlopen is not _DEFAULT_URLOPEN:
                ctx_mgr = urllib.request.urlopen(req, timeout=timeout)
            else:
                opener = urllib.request.build_opener(_SafeRedirectHandler())
                ctx_mgr = opener.open(req, timeout=timeout)
            with ctx_mgr as response:
                data = response.read(_MAX_FETCH_BYTES + 1)
                if len(data) > _MAX_FETCH_BYTES:
                    logger.warning(
                        "Réponse HTTP trop volumineuse (> %d octets) ignorée pour %s",
                        _MAX_FETCH_BYTES,
                        candidate,
                    )
                    return None
                return data
        except Exception as exc:  # noqa: BLE001
            logger.debug("Échec téléchargement %s: %s", candidate, exc)
    return None


def _extract_links(html: bytes, base_url: str) -> list[str]:
    """Récupère les liens HTTP/HTTPS .cer/.crt/.der/.pem depuis une page HTML."""
    urls: list[str] = []
    for m in HREF_RE.finditer(html):
        if len(urls) >= _MAX_LINKS_PER_PAGE:
            logger.warning(
                "Nombre maximal de liens par page atteint (%d) pour %s",
                _MAX_LINKS_PER_PAGE,
                base_url,
            )
            break
        href = unescape(m.group(1).decode("utf-8", "ignore"))
        href = urllib.parse.urljoin(base_url, href)
        if _is_safe_http_url(href) is None:
            continue
        if re.search(r"\.(cer|crt|der|pem)(\?.*)?$", href, re.IGNORECASE):
            urls.append(href)
    return urls


def _extract_ca_id(tsp_elem: ET.Element) -> str | None:
    """Récupère 'FRxx' depuis TSPTradeName (ou à défaut dans TSPName)."""
    trade_names = [
        (n.text or "").strip()
        for n in tsp_elem.findall("./tsl:TSPInformation/tsl:TSPTradeName/tsl:Name", NS)
    ]
    for tn in trade_names:
        if _CA_ID_RE.fullmatch(tn):
            return tn
    for n in tsp_elem.findall("./tsl:TSPInformation/tsl:TSPName/tsl:Name", NS):
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
        if source.lstrip().startswith("<"):
            return source.encode("utf-8")
        try:
            path = Path(source)
            if path.is_file():
                return path.read_bytes()
        except OSError:
            pass
        return source.encode("utf-8")
    data = source.read()
    return data.encode("utf-8") if isinstance(data, str) else data


def _parse_tsl_bytes(
    xml_bytes: bytes,
    *,
    include_test_ca: bool = False,
) -> tuple[list[_CertRecord], dict[str, list[str]], TslMetadata]:
    if not xml_bytes or _FORBIDDEN_XML_DECL_RE.search(xml_bytes):
        raise TrustSignatureError(
            "Document XML TSL vide ou contenant une déclaration DOCTYPE/ENTITY interdite."
        )

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ResolverUnavailableError(f"XML TSL invalide: {exc}") from exc

    expected_root_tag = f"{{{NS['tsl']}}}TrustServiceStatusList"
    if root.tag != expected_root_tag:
        raise TrustSignatureError(
            f"Racine XML TSL inattendue: {root.tag!r} ({expected_root_tag!r} attendu)."
        )

    # Retirer tout bloc ds:Signature avant extraction structurelle (anti-XSW)
    sig_tag = f"{{{NS['ds']}}}Signature"
    for child in list(root):
        if child.tag == sig_tag:
            root.remove(child)

    seq_txt = root.findtext(
        "./tsl:SchemeInformation/tsl:TSLSequenceNumber", default="", namespaces=NS
    )
    seq_num: int | None = None
    if seq_txt.strip().isdigit():
        seq_num = int(seq_txt.strip())

    issue_dt = _parse_iso_datetime(
        root.findtext(
            "./tsl:SchemeInformation/tsl:ListIssueDateTime", default="", namespaces=NS
        )
    )
    next_upd = _parse_iso_datetime(
        root.findtext(
            "./tsl:SchemeInformation/tsl:NextUpdate/tsl:dateTime",
            default="",
            namespaces=NS,
        )
    )
    metadata = TslMetadata(
        sequence_number=seq_num,
        issue_date=issue_dt,
        next_update=next_upd,
        signer_cn=None,
    )

    records: list[_CertRecord] = []
    tsp_uris: dict[str, list[str]] = {}

    for tsp in root.findall(
        "./tsl:TrustServiceProviderList/tsl:TrustServiceProvider", NS
    ):
        ca_id = _extract_ca_id(tsp)
        if not ca_id:
            continue
        ca_id = ca_id.upper()
        if not include_test_ca and ca_id == "FR00":
            continue

        uris: list[str] = []
        for u in tsp.findall("./tsl:TSPInformation/tsl:TSPInformationURI/tsl:URI", NS):
            if u.text:
                uris.append(u.text.strip())
        if uris:
            tsp_uris[ca_id] = list(dict.fromkeys(uris))

        for svc in tsp.findall("./tsl:TSPServices/tsl:TSPService", NS):
            svc_status = (
                svc.findtext(
                    "./tsl:ServiceInformation/tsl:ServiceStatus",
                    default="",
                    namespaces=NS,
                )
                or ""
            ).strip()
            if svc_status != SVCSTATUS_INACCORD:
                continue

            status_start = _parse_iso_datetime(
                svc.findtext(
                    "./tsl:ServiceInformation/tsl:StatusStartingTime",
                    default="",
                    namespaces=NS,
                )
            )

            for cert_b64_elem in svc.findall(
                "./tsl:ServiceInformation/tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate",
                NS,
            ):
                b64 = (cert_b64_elem.text or "").strip()
                if not b64:
                    continue
                try:
                    der = base64.b64decode(b64, validate=True)
                    cert = x509.load_der_x509_certificate(der)
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "Certificat X.509 TSL invalide ignoré pour %s: %s", ca_id, exc
                    )
                    continue
                records.append(
                    _CertRecord(
                        ca_id=ca_id,
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
    except Exception:  # noqa: BLE001
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


def _is_crl_fresh_with_margin(
    crl: x509.CertificateRevocationList,
    *,
    evaluation_date: dt.date | None = None,
    refresh_margin: dt.timedelta = dt.timedelta(0),
) -> bool:
    """Indique si la CRL est applicable et reste valide au-delà de ``refresh_margin``."""
    if not is_crl_applicable(crl, evaluation_date):
        return False
    next_update = crl.next_update_utc
    if next_update is None:
        return False
    if refresh_margin <= dt.timedelta(0):
        return True
    if evaluation_date is not None:
        ref_dt = dt.datetime.combine(evaluation_date, dt.time.min, tzinfo=dt.UTC)
        return next_update > ref_dt + refresh_margin
    return next_update > dt.datetime.now(dt.UTC) + refresh_margin


class KeyResolver:
    """Résout et valide une clé publique de vérification 2D-Doc depuis la TSL ANTS.

    Aucun fallback silencieux n'est autorisé : ``(ca_id, cert_id)`` doit correspondre
    à un certificat feuille validé cryptographiquement contre son AC de la TSL.
    Supporte la coexistence de plusieurs certificats (rotation) pour un même ``(ca_id, cert_id)``.
    """

    def __init__(
        self,
        ca_records: Mapping[str, Sequence[_CertRecord]] | None = None,
        leaf_index: Mapping[tuple[str, str], x509.Certificate] | None = None,
        crls_by_ca: Mapping[str, Sequence[x509.CertificateRevocationList]]
        | None = None,
        tsl_metadata: TslMetadata | None = None,
        leaf_candidates: Mapping[tuple[str, str], Sequence[x509.Certificate]]
        | None = None,
        require_crls: bool = True,
    ) -> None:
        self._ca_records: dict[str, list[_CertRecord]] = {
            ca.upper(): list(recs) for ca, recs in (ca_records or {}).items()
        }
        self._leaf_candidates: dict[tuple[str, str], list[x509.Certificate]] = {}
        self._leaf_index: dict[tuple[str, str], x509.Certificate] = {}
        self._crl_lock = threading.RLock()
        self._crls_by_ca: dict[str, list[x509.CertificateRevocationList]] = {}
        self._crls_by_issuer: dict[str, list[x509.CertificateRevocationList]] = {}
        self._require_crls = require_crls

        if leaf_candidates:
            for (ca, cid), certs in leaf_candidates.items():
                key = (ca.upper(), cid.upper())
                self._merge_leaf_candidates(key, certs)

        if leaf_index:
            for (ca, cid), cert in leaf_index.items():
                key = (ca.upper(), cid.upper())
                self._merge_leaf_candidates(key, [cert])

        self._tsl_metadata = tsl_metadata
        for ca_id, crls in (crls_by_ca or {}).items():
            for crl in crls:
                self.add_crl(ca_id, crl)

    def _merge_leaf_candidates(
        self, key: tuple[str, str], certs: Sequence[x509.Certificate]
    ) -> None:
        bucket = self._leaf_candidates.setdefault(key, [])
        seen_certificates = {_cert_fingerprint(c) for c in bucket}
        for cert in certs:
            fingerprint = _cert_fingerprint(cert)
            if fingerprint not in seen_certificates:
                bucket.append(cert)
                seen_certificates.add(fingerprint)
        if bucket:
            bucket.sort(
                key=lambda c: (
                    c.not_valid_after_utc,
                    c.not_valid_before_utc,
                    c.serial_number,
                ),
                reverse=True,
            )
            self._leaf_index[key] = bucket[0]

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
        now_utc = dt.datetime.now(dt.UTC)
        aware_next = (
            next_upd if next_upd.tzinfo is not None else next_upd.replace(tzinfo=dt.UTC)
        )
        return (
            TrustListFreshness.STALE
            if now_utc > aware_next
            else TrustListFreshness.FRESH
        )

    def _match_ca_candidates_for_leaf(
        self,
        ca_id: str,
        leaf_cert: x509.Certificate,
        *,
        expected_cert_id: str | None = None,
    ) -> list[tuple[_CertRecord, str]]:
        ca = ca_id.upper()
        records = self._ca_records.get(ca)
        if not records:
            raise UnknownCAError(f"Autorité de Certification inconnue: {ca_id}")

        matches: list[tuple[_CertRecord, str]] = []
        last_err: UntrustedCertificateError | None = None
        for rec in records:
            try:
                cid = validate_leaf_against_ca(
                    leaf_cert, rec.cert, expected_cert_id=expected_cert_id
                )
                matches.append((rec, cid))
            except UntrustedCertificateError as exc:
                last_err = exc
        if matches:
            return matches
        raise last_err or UntrustedCertificateError(
            f"Le certificat feuille n'est approuvé par aucune AC pour {ca_id}."
        )

    def _match_ca_for_leaf(
        self,
        ca_id: str,
        leaf_cert: x509.Certificate,
        *,
        expected_cert_id: str | None = None,
    ) -> tuple[_CertRecord, str]:
        return self._match_ca_candidates_for_leaf(
            ca_id, leaf_cert, expected_cert_id=expected_cert_id
        )[0]

    def add_leaf(self, ca_id: str, leaf_cert: x509.Certificate) -> str:
        """Valide puis indexe un certificat feuille (rotation supportée) pour une AC de la TSL."""
        ca = ca_id.upper()
        _, cert_id = self._match_ca_for_leaf(ca, leaf_cert)
        key = (ca, cert_id)
        existing = self._leaf_candidates.get(key, [])
        fingerprint = _cert_fingerprint(leaf_cert)
        if any(_cert_fingerprint(c) == fingerprint for c in existing):
            return cert_id
        if existing:
            logger.info(
                "Rotation / certificat supplémentaire indexé pour (%s, %s): série %s",
                ca,
                cert_id,
                leaf_cert.serial_number,
            )
        self._merge_leaf_candidates(key, [leaf_cert])
        return cert_id

    def add_crl(self, ca_id: str, crl: x509.CertificateRevocationList) -> None:
        """Valide une CRL et l'associe au certificat émetteur exact."""
        ca = ca_id.upper()
        records = self._ca_records.get(ca)
        if not records:
            raise UnknownCAError(
                f"Autorité de Certification inconnue pour CRL: {ca_id}"
            )

        last_err: TrustSignatureError | None = None
        matched_issuers: list[str] = []
        for rec in records:
            try:
                validate_crl_against_ca(crl, rec.cert)
                matched_issuers.append(_cert_fingerprint(rec.cert))
            except TrustSignatureError as exc:
                last_err = exc
        if matched_issuers:
            with self._crl_lock:
                self._crls_by_ca.setdefault(ca, []).append(crl)
                for issuer_key in matched_issuers:
                    self._crls_by_issuer.setdefault(issuer_key, []).append(crl)
            return
        raise last_err or TrustSignatureError(
            f"CRL invalide ou non signée par l'AC {ca_id}."
        )

    def _replace_issuer_crl(
        self,
        ca_id: str,
        issuer_key: str,
        crl: x509.CertificateRevocationList,
    ) -> bool:
        """Remplace la CRL si elle n'est pas plus ancienne que celle déjà chargée."""
        ca = ca_id.upper()
        with self._crl_lock:
            previous = self._crls_by_issuer.get(issuer_key, [])
            last_update = crl.last_update_utc
            if last_update is not None and any(
                existing.last_update_utc is not None
                and existing.last_update_utc > last_update
                for existing in previous
            ):
                return False
            self._crls_by_issuer[issuer_key] = [crl]
            previous_ids = {id(old) for old in previous}
            still_referenced = {
                id(existing)
                for other_key, other_crls in self._crls_by_issuer.items()
                if other_key != issuer_key
                for existing in other_crls
            }
            existing_ca_crls = self._crls_by_ca.get(ca, [])
            updated_ca_crls = [
                existing
                for existing in existing_ca_crls
                if id(existing) not in previous_ids or id(existing) in still_referenced
            ]
            updated_ca_crls.append(crl)
            self._crls_by_ca[ca] = updated_ca_crls
            return True

    def _active_issuer_leaves(
        self,
    ) -> dict[tuple[str, str], tuple[x509.Certificate, list[x509.Certificate]]]:
        """Regroupe les certificats feuilles validés par émetteur actif ``(ca_id, issuer_fp)``."""
        groups: dict[
            tuple[str, str], tuple[x509.Certificate, list[x509.Certificate]]
        ] = {}
        for (ca_id, _), leaves in self._leaf_candidates.items():
            for leaf in leaves:
                for rec, _ in self._match_ca_candidates_for_leaf(ca_id, leaf):
                    key = (ca_id, _cert_fingerprint(rec.cert))
                    entry = groups.setdefault(key, (rec.cert, []))
                    entry[1].append(leaf)
        return groups

    def _active_issuer_certificates(self) -> dict[tuple[str, str], x509.Certificate]:
        return {
            key: ca_cert for key, (ca_cert, _) in self._active_issuer_leaves().items()
        }

    def get_expired_crl_cas(
        self,
        *,
        evaluation_date: dt.date | None = None,
        refresh_margin: dt.timedelta = dt.timedelta(0),
    ) -> tuple[str, ...]:
        """Retourne les ``ca_id`` triés dont au moins un émetteur actif n'a pas de CRL fraîche."""
        if refresh_margin < dt.timedelta(0):
            raise ValueError("refresh_margin ne peut pas être négatif.")
        expired: set[str] = set()
        active_issuers = self._active_issuer_certificates()
        with self._crl_lock:
            for ca_id, issuer_key in active_issuers:
                crls = self._crls_by_issuer.get(issuer_key, ())
                if not any(
                    _is_crl_fresh_with_margin(
                        crl,
                        evaluation_date=evaluation_date,
                        refresh_margin=refresh_margin,
                    )
                    for crl in crls
                ):
                    expired.add(ca_id)
        return tuple(sorted(expired))

    def has_expired_crls(
        self,
        *,
        evaluation_date: dt.date | None = None,
        refresh_margin: dt.timedelta = dt.timedelta(0),
    ) -> bool:
        """Indique si au moins une AC active possède une CRL absente, expirée ou proche de l'expiration."""
        return bool(
            self.get_expired_crl_cas(
                evaluation_date=evaluation_date,
                refresh_margin=refresh_margin,
            )
        )

    def refresh_crls(
        self,
        *,
        timeout: int = 15,
        only_expired: bool = True,
        refresh_margin: dt.timedelta = dt.timedelta(hours=24),
        ca_ids: Iterable[str] | None = None,
        evaluation_date: dt.date | None = None,
    ) -> CrlRefreshResult:
        """Rafraîchit explicitement les CRLs en mémoire pour les AC connues.

        Aucun appel réseau n'est effectué tant que cette méthode n'est pas appelée
        explicitement. Les CRLs téléchargées sont vérifiées cryptographiquement
        contre le certificat émetteur de la TSL avant remplacement atomique en mémoire.
        Un échec sur une AC n'empêche pas le rafraîchissement des autres AC et ne
        supprime jamais une CRL fraîche déjà chargée.
        """
        if timeout <= 0:
            raise ValueError("timeout doit être strictement positif.")
        if refresh_margin < dt.timedelta(0):
            raise ValueError("refresh_margin ne peut pas être négatif.")

        issuer_leaves = self._active_issuer_leaves()
        issuers_by_ca: dict[
            str, list[tuple[str, x509.Certificate, list[x509.Certificate]]]
        ] = {}
        for (ca_id, issuer_key), (ca_cert, leaves) in issuer_leaves.items():
            issuers_by_ca.setdefault(ca_id, []).append((issuer_key, ca_cert, leaves))

        failed_cas: dict[str, str] = {}
        if ca_ids is not None:
            requested = sorted({c.strip().upper() for c in ca_ids if c and c.strip()})
            ordered_cas: list[str] = []
            for ca_id in requested:
                if ca_id in issuers_by_ca:
                    ordered_cas.append(ca_id)
                elif ca_id not in self._ca_records:
                    failed_cas[ca_id] = "unknown_ca"
                    logger.warning(
                        "Rafraîchissement CRL ignoré pour AC inconnue: %s", ca_id
                    )
        else:
            ordered_cas = sorted(issuers_by_ca.keys())

        refreshed_cas: list[str] = []
        skipped_fresh_cas: list[str] = []

        for ca_id in ordered_cas:
            ca_refreshed = False
            ca_skipped = False
            ca_failures: list[str] = []

            for issuer_key, ca_cert, leaves in issuers_by_ca[ca_id]:
                with self._crl_lock:
                    existing_crls = tuple(self._crls_by_issuer.get(issuer_key, ()))

                if only_expired and any(
                    _is_crl_fresh_with_margin(
                        crl,
                        evaluation_date=evaluation_date,
                        refresh_margin=refresh_margin,
                    )
                    for crl in existing_crls
                ):
                    ca_skipped = True
                    continue

                crl_urls = extract_crl_urls_from_certs(leaves)
                if not crl_urls:
                    ca_failures.append("no_crl_distribution_point")
                    logger.warning(
                        "Aucune URL CRL Distribution Point trouvée pour %s/%s",
                        ca_id,
                        issuer_key[:12],
                    )
                    continue

                issuer_updated = False
                last_reason = "fetch_failed"
                for crl_url in crl_urls:
                    crl_bytes = _fetch_bytes(crl_url, timeout=timeout)
                    if not crl_bytes:
                        last_reason = "fetch_failed"
                        continue
                    try:
                        crl = _load_crl_bytes(crl_bytes)
                    except Exception as exc:  # noqa: BLE001
                        last_reason = "invalid_crl_format"
                        logger.warning(
                            "CRL illisible ignorée (%s/%s): %s",
                            ca_id,
                            issuer_key[:12],
                            exc,
                        )
                        continue
                    try:
                        validate_crl_against_ca(crl, ca_cert)
                    except TrustSignatureError as exc:
                        last_reason = "invalid_crl_signature"
                        logger.warning(
                            "CRL rejetée par validation PKI (%s/%s): %s",
                            ca_id,
                            issuer_key[:12],
                            exc,
                        )
                        continue
                    if not is_crl_applicable(crl, evaluation_date):
                        last_reason = "crl_not_applicable"
                        logger.warning(
                            "CRL non applicable à la date d'évaluation ignorée (%s/%s)",
                            ca_id,
                            issuer_key[:12],
                        )
                        continue

                    replaced = self._replace_issuer_crl(ca_id, issuer_key, crl)
                    ca_refreshed = ca_refreshed or replaced
                    issuer_updated = True
                    if replaced:
                        logger.info(
                            "CRL rafraîchie en mémoire pour %s/%s (next_update=%s)",
                            ca_id,
                            issuer_key[:12],
                            crl.next_update_utc,
                        )
                    else:
                        logger.info(
                            "CRL plus ancienne ignorée pour %s/%s (last_update=%s)",
                            ca_id,
                            issuer_key[:12],
                            crl.last_update_utc,
                        )
                    break

                if not issuer_updated:
                    ca_failures.append(last_reason)
                    logger.warning(
                        "Échec du rafraîchissement CRL pour %s/%s (%s)",
                        ca_id,
                        issuer_key[:12],
                        last_reason,
                    )

            if ca_refreshed:
                refreshed_cas.append(ca_id)
            if ca_skipped and not ca_refreshed and not ca_failures:
                skipped_fresh_cas.append(ca_id)
            if ca_failures:
                failed_cas[ca_id] = ", ".join(dict.fromkeys(ca_failures))

        expired_cas: list[str] = []
        with self._crl_lock:
            for ca_id in ordered_cas:
                if any(
                    not any(
                        is_crl_applicable(crl, evaluation_date)
                        for crl in self._crls_by_issuer.get(issuer_key, ())
                    )
                    for issuer_key, _, _ in issuers_by_ca[ca_id]
                ):
                    expired_cas.append(ca_id)

        return CrlRefreshResult(
            refreshed_cas=tuple(sorted(refreshed_cas)),
            skipped_fresh_cas=tuple(sorted(skipped_fresh_cas)),
            failed_cas=failed_cas,
            expired_cas=tuple(sorted(expired_cas)),
        )

    def _ensure_crl_coverage(
        self,
        *,
        require_current: bool = False,
        evaluation_date: dt.date | None = None,
    ) -> None:
        """Exige une CRL pour chaque émetteur retenu, courante si demandé."""
        missing: list[str] = []
        not_current: list[str] = []
        active_issuers = self._active_issuer_certificates()
        with self._crl_lock:
            for ca_id, issuer_key in active_issuers:
                crls = tuple(self._crls_by_issuer.get(issuer_key, ()))
                if not crls:
                    missing.append(f"{ca_id}/{issuer_key[:12]}")
                elif require_current and not any(
                    is_crl_applicable(crl, evaluation_date) for crl in crls
                ):
                    not_current.append(f"{ca_id}/{issuer_key[:12]}")

        if missing or not_current:
            details: list[str] = []
            if missing:
                details.append(f"CRL(s) manquante(s): {', '.join(sorted(missing))}")
            if not_current:
                details.append(
                    f"CRL(s) expirée(s), futures ou sans NextUpdate: {', '.join(sorted(not_current))}"
                )
            raise ResolverUnavailableError(
                "Couverture CRL insuffisante pour les émetteurs de feuilles ("
                + "; ".join(details)
                + ")."
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
        include_test_ca: bool = False,
        leaf_certs_by_ca: Mapping[str, Sequence[x509.Certificate]] | None = None,
        crls_by_ca: Mapping[str, Sequence[x509.CertificateRevocationList]]
        | None = None,
        require_crls: bool = True,
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

        recs, tsp_uris, parsed_meta = _parse_tsl_bytes(
            xml_bytes, include_test_ca=include_test_ca
        )
        meta = verified_meta or parsed_meta

        recs.sort(
            key=lambda r: (
                r.ca_id,
                r.status_start or dt.datetime.min.replace(tzinfo=dt.UTC),
            ),
            reverse=True,
        )

        ca_records: dict[str, list[_CertRecord]] = {}
        for rec in recs:
            ca_records.setdefault(rec.ca_id, []).append(rec)

        resolver = cls(
            ca_records=ca_records,
            tsl_metadata=meta,
            require_crls=require_crls,
        )

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

                seen_certificates: set[str] = set()
                for cert in downloaded:
                    fingerprint = _cert_fingerprint(cert)
                    if fingerprint in seen_certificates:
                        continue
                    seen_certificates.add(fingerprint)
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
        require_crls: bool = True,
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
            require_crls=require_crls,
        )

        # 1) Chargement des feuilles depuis trusted_leaves/<CA_ID>.pem
        loaded_leaf_count = 0
        try:
            leaves_dir = resolved_dir.joinpath("trusted_leaves")
            has_leaves_dir = leaves_dir.is_dir()
        except Exception:  # noqa: BLE001
            leaves_dir = None
            has_leaves_dir = False

        if has_leaves_dir and leaves_dir is not None:
            pem_files = sorted(
                (
                    item
                    for item in leaves_dir.iterdir()
                    if item.is_file() and item.name.endswith(".pem")
                ),
                key=lambda p: p.name,
            )
            for pem_item in pem_files:
                ca_id = pem_item.name[:-4].upper()
                if not _CA_ID_RE.fullmatch(ca_id):
                    logger.warning(
                        "Fichier de feuilles ignoré (nom ca_id invalide): %s",
                        pem_item.name,
                    )
                    continue
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
        except Exception:  # noqa: BLE001
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
        except Exception:  # noqa: BLE001
            crls_dir = None
            has_crls_dir = False

        if has_crls_dir and crls_dir is not None:
            crl_files = sorted(
                (
                    item
                    for item in crls_dir.iterdir()
                    if item.is_file() and item.name.endswith(".crl")
                ),
                key=lambda p: p.name,
            )
            for crl_item in crl_files:
                file_match = _CRL_FILE_STEM_RE.fullmatch(crl_item.name[:-4])
                if file_match is None:
                    logger.warning(
                        "Fichier CRL ignoré (nom de fichier invalide): %s",
                        crl_item.name,
                    )
                    continue
                ca_id = file_match.group(1).upper()
                try:
                    crl_bytes = crl_item.read_bytes()
                    crl = _load_crl_bytes(crl_bytes)
                except Exception as exc:
                    raise ResolverUnavailableError(
                        f"CRL corrompue pour {ca_id} ({crl_item.name}): {exc}"
                    ) from exc
                resolver.add_crl(ca_id, crl)

        if require_crls:
            resolver._ensure_crl_coverage()

        return resolver

    @classmethod
    def from_network(
        cls,
        tsl_url: str = DEFAULT_TSL_URL,
        *,
        root_ca_cert: x509.Certificate | None = None,
        timeout: int = 15,
        evaluation_date: dt.date | None = None,
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

        # Téléchargement des CRLs pour chaque certificat émetteur réellement retenu.
        issuer_groups: dict[
            str, tuple[str, x509.Certificate, list[x509.Certificate]]
        ] = {}
        for (ca_id, _), candidates in resolver._leaf_candidates.items():
            for leaf in candidates:
                matched_ca, _ = resolver._match_ca_for_leaf(ca_id, leaf)
                issuer_key = _cert_fingerprint(matched_ca.cert)
                group = issuer_groups.setdefault(
                    issuer_key, (ca_id, matched_ca.cert, [])
                )
                group[2].append(leaf)

        if not issuer_groups:
            raise ResolverUnavailableError(
                "Aucun certificat feuille vérifié n'a pu être téléchargé."
            )

        for _issuer_key, (ca_id, ca_cert, ca_leaves) in issuer_groups.items():
            for crl_url in extract_crl_urls_from_certs(ca_leaves):
                crl_bytes = _fetch_bytes(crl_url, timeout=timeout)
                if not crl_bytes:
                    continue
                try:
                    crl = _load_crl_bytes(crl_bytes)
                    validate_crl_against_ca(crl, ca_cert)
                    if not is_crl_applicable(crl, evaluation_date):
                        logger.warning(
                            "CRL non applicable à la date courante ignorée (%s / %s)",
                            ca_id,
                            crl_url,
                        )
                        continue
                    resolver.add_crl(ca_id, crl)
                    break
                except (TrustSignatureError, ValueError) as exc:
                    logger.warning("CRL ignorée (%s / %s): %s", ca_id, crl_url, exc)

        resolver._ensure_crl_coverage(
            require_current=True, evaluation_date=evaluation_date
        )
        return resolver

    def resolve(self, ca_id: str, cert_id: str) -> CertificatePublicKeyTypes:
        """Retourne la clé publique validée (chaîne X.509 AC -> feuille) pour ``(ca_id, cert_id)``.

        Aucun fallback sur certificat unique n'est effectué.
        Attention : cette méthode bas niveau ne contrôle ni la révocation (CRL)
        ni les dates de validité ni la fraîcheur de la TSL. Pour une vérification
        complète d'un 2D-Doc, utiliser ``resolve_for_verification()`` ou ``Decoded2DDoc.verify()``.
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

    def _resolve_candidate_set_for_verification(
        self,
        ca_id: str,
        cert_id: str,
        *,
        reference_date: dt.date | None,
        evaluation_date: dt.date | None = None,
        tsl_eval_date: dt.date | None = None,
        strict_tsl_freshness: bool = True,
    ) -> VerifiedCandidateSet:
        """Résout les candidats et conserve toute indisponibilité concurrente."""
        effective_eval_date = evaluation_date or dt.datetime.now(dt.UTC).date()
        effective_tsl_eval = (
            tsl_eval_date if tsl_eval_date is not None else evaluation_date
        )

        freshness = self.get_tsl_freshness(evaluation_date=effective_tsl_eval)
        if strict_tsl_freshness and freshness != TrustListFreshness.FRESH:
            raise TrustListExpiredError(
                f"TSL périmée ou sans date NextUpdate valide (freshness={freshness.value}, NextUpdate={self.tsl_next_update})."
            )

        ca = ca_id.upper()
        cid = (cert_id or "").upper()

        if ca not in self._ca_records:
            raise UnknownCAError(f"AC inconnue dans la TSL: {ca_id}")

        candidates = self._leaf_candidates.get((ca, cid))
        if not candidates:
            fallback_single = self._leaf_index.get((ca, cid))
            if fallback_single is not None:
                candidates = [fallback_single]
            else:
                raise UnknownCertificateError(
                    f"Certificat introuvable pour AC={ca_id} cert_id={cert_id}"
                )

        valid_contexts: list[VerifiedCertificateContext] = []
        validity_err: CertificateValidityError | None = None
        revoked_err: CertificateRevokedError | None = None
        unavailable_err: ResolverUnavailableError | None = None
        untrusted_err: UntrustedCertificateError | None = None

        for leaf_cert in candidates:
            try:
                matched_cas = self._match_ca_candidates_for_leaf(
                    ca, leaf_cert, expected_cert_id=cid
                )
            except UntrustedCertificateError as exc:
                untrusted_err = untrusted_err or exc
                continue

            for matched_ca, _ in matched_cas:
                try:
                    if self._require_crls:
                        with self._crl_lock:
                            issuer_crls = tuple(
                                self._crls_by_issuer.get(
                                    _cert_fingerprint(matched_ca.cert), ()
                                )
                            )
                        check_certificate_revocation(
                            leaf_cert,
                            issuer_crls,
                            reference_date,
                            evaluation_date,
                        )
                except CertificateRevokedError as exc:
                    revoked_err = revoked_err or exc
                    continue
                except ResolverUnavailableError as exc:
                    unavailable_err = unavailable_err or exc
                    continue

                try:
                    validate_certificate_dates(
                        leaf_cert,
                        matched_ca.cert,
                        reference_date=reference_date,
                        evaluation_date=effective_eval_date,
                        ca_status_start=matched_ca.status_start,
                    )
                except CertificateValidityError as exc:
                    validity_err = validity_err or exc
                    continue

                valid_contexts.append(
                    VerifiedCertificateContext(
                        ca_id=ca,
                        cert_id=cid,
                        leaf_cert=leaf_cert,
                        ca_cert=matched_ca.cert,
                        tsl_sequence_number=self.tsl_sequence_number,
                        tsl_next_update=self.tsl_next_update,
                        tsl_freshness=freshness,
                    )
                )

        if valid_contexts:
            return VerifiedCandidateSet(
                contexts=valid_contexts,
                unavailable_detail=(
                    str(unavailable_err) if unavailable_err is not None else None
                ),
            )
        if unavailable_err is not None:
            raise unavailable_err
        if validity_err is not None:
            raise validity_err
        if revoked_err is not None:
            raise revoked_err
        if untrusted_err is not None:
            raise untrusted_err
        raise UnknownCertificateError(
            f"Certificat introuvable pour AC={ca_id} cert_id={cert_id}"
        )

    def resolve_candidate_set_for_verification(
        self,
        ca_id: str,
        cert_id: str,
        *,
        reference_date: dt.date | None,
        evaluation_date: dt.date | None = None,
        tsl_eval_date: dt.date | None = None,
        strict_tsl_freshness: bool = True,
    ) -> VerifiedCandidateSet:
        """Préserve les surcharges existantes tout en exposant l'incertitude."""
        if (
            type(self).resolve_candidates_for_verification
            is not KeyResolver.resolve_candidates_for_verification
        ):
            capture = _CandidateResolutionCapture(
                resolver=self,
                request=(
                    ca_id,
                    cert_id,
                    reference_date,
                    evaluation_date,
                    tsl_eval_date,
                    strict_tsl_freshness,
                ),
            )
            token = _CANDIDATE_RESOLUTION_CAPTURE.set(capture)
            try:
                contexts = self.resolve_candidates_for_verification(
                    ca_id,
                    cert_id,
                    reference_date=reference_date,
                    evaluation_date=evaluation_date,
                    tsl_eval_date=tsl_eval_date,
                    strict_tsl_freshness=strict_tsl_freshness,
                )
            finally:
                _CANDIDATE_RESOLUTION_CAPTURE.reset(token)
            captured = capture.result
            return VerifiedCandidateSet(
                contexts=contexts,
                unavailable_detail=(
                    captured.unavailable_detail if captured is not None else None
                ),
            )
        return self._resolve_candidate_set_for_verification(
            ca_id,
            cert_id,
            reference_date=reference_date,
            evaluation_date=evaluation_date,
            tsl_eval_date=tsl_eval_date,
            strict_tsl_freshness=strict_tsl_freshness,
        )

    def resolve_candidates_for_verification(
        self,
        ca_id: str,
        cert_id: str,
        *,
        reference_date: dt.date | None,
        evaluation_date: dt.date | None = None,
        tsl_eval_date: dt.date | None = None,
        strict_tsl_freshness: bool = True,
    ) -> list[VerifiedCertificateContext]:
        """Résout tous les certificats candidats valides et non révoqués."""
        result = self._resolve_candidate_set_for_verification(
            ca_id,
            cert_id,
            reference_date=reference_date,
            evaluation_date=evaluation_date,
            tsl_eval_date=tsl_eval_date,
            strict_tsl_freshness=strict_tsl_freshness,
        )
        capture = _CANDIDATE_RESOLUTION_CAPTURE.get()
        request = (
            ca_id,
            cert_id,
            reference_date,
            evaluation_date,
            tsl_eval_date,
            strict_tsl_freshness,
        )
        if (
            capture is not None
            and capture.resolver is self
            and capture.result is None
            and capture.request == request
        ):
            capture.result = result
        return result.contexts

    def resolve_for_verification(
        self,
        ca_id: str,
        cert_id: str,
        *,
        reference_date: dt.date | None,
        evaluation_date: dt.date | None = None,
        tsl_eval_date: dt.date | None = None,
        strict_tsl_freshness: bool = True,
    ) -> VerifiedCertificateContext:
        """Exécute la chaîne complète de résolution et validation PKI pour un 2D-DOC."""
        return self.resolve_candidates_for_verification(
            ca_id,
            cert_id,
            reference_date=reference_date,
            evaluation_date=evaluation_date,
            tsl_eval_date=tsl_eval_date,
            strict_tsl_freshness=strict_tsl_freshness,
        )[0]

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


def refresh_default_crls(
    *,
    timeout: int = 15,
    only_expired: bool = True,
    refresh_margin: dt.timedelta = dt.timedelta(hours=24),
    ca_ids: Iterable[str] | None = None,
    evaluation_date: dt.date | None = None,
) -> CrlRefreshResult:
    """Rafraîchit explicitement en mémoire les CRLs du ``KeyResolver`` par défaut.

    Aucun appel réseau n'est effectué tant que cette fonction n'est pas appelée
    explicitement par l'intégrateur.
    """
    return get_default_key_resolver().refresh_crls(
        timeout=timeout,
        only_expired=only_expired,
        refresh_margin=refresh_margin,
        ca_ids=ca_ids,
        evaluation_date=evaluation_date,
    )


def __getattr__(name: str) -> Any:
    if name == "local_key_resolver":
        return get_default_key_resolver()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
