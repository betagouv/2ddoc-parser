from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import urllib.error
import urllib.request
import warnings
import xml.dom.minidom as minidom
from http.client import HTTPMessage
from pathlib import Path

import lxml.etree as LET
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from fr_2ddoc_parser.api import decode_2d_doc
from fr_2ddoc_parser.crypto import key_resolver as key_resolver_mod
from fr_2ddoc_parser.crypto import sync_trust_store as sync_mod
from fr_2ddoc_parser.crypto.key_resolver import (
    _MAX_FETCH_BYTES,
    _MAX_LINKS_PER_PAGE,
    ENV_TRUST_STORE_DIR,
    KeyResolver,
    _extract_links,
    _fetch_bytes,
    _is_safe_http_url,
    _parse_tsl_bytes,
    _SafeRedirectHandler,
    get_default_key_resolver,
    reset_default_key_resolver,
)
from fr_2ddoc_parser.crypto.trust_validator import (
    TslMetadata,
    _canonicalize_subtree,
    check_certificate_revocation,
    validate_crl_against_ca,
    validate_leaf_against_ca,
    verify_tsl_xml_signature,
)
from fr_2ddoc_parser.exception.exceptions import (
    CertificateValidityError,
    ResolverUnavailableError,
    TrustListExpiredError,
    TrustSignatureError,
    UnknownCAError,
    UnknownCertificateError,
    UntrustedCertificateError,
)
from fr_2ddoc_parser.model.models import (
    TrustListFreshness,
    VerificationStatus,
)


def _date_to_hex_days(d: dt.date) -> str:
    days = (d - dt.date(2000, 1, 1)).days
    return f"{days:04X}"


def _build_signed_2ddoc(
    *,
    ca_id: str,
    cert_id: str,
    issue_date: dt.date | None,
    signature_date: dt.date | None,
    private_key: ec.EllipticCurvePrivateKey | None,
    doc_type: str = "00",
    payload_body: str = "26FR247500010JEAN/DUPONT\x1d20\x1d21\x1d221 RUE TEST\x1d23\x1d25PARIS\x1d",
) -> str:
    issue_hex = _date_to_hex_days(issue_date) if issue_date else "FFFF"
    sig_hex = _date_to_hex_days(signature_date) if signature_date else "FFFF"
    header = f"DC04{ca_id}{cert_id}{issue_hex}{sig_hex}{doc_type}01FR"
    sign_payload = (header + payload_body).encode("utf-8")
    if private_key is None:
        return header + payload_body

    der_sig = private_key.sign(sign_payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    coord_size = (private_key.curve.key_size + 7) // 8
    raw_sig = r.to_bytes(coord_size, "big") + s.to_bytes(coord_size, "big")
    sig_b32 = base64.b32encode(raw_sig).decode("ascii").rstrip("=")
    return f"{header}{payload_body}\x1f{sig_b32}"


def _make_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _make_name(cn: str, org: str = "TEST ORG") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _build_ca_cert(
    subject_cn: str,
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    *,
    issuer_cert: x509.Certificate | None = None,
    issuer_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None = None,
    not_before: dt.datetime,
    not_after: dt.datetime,
    serial: int | None = None,
) -> x509.Certificate:
    subject = _make_name(subject_cn)
    issuer = issuer_cert.subject if issuer_cert is not None else subject
    signing_key = issuer_key or private_key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )
    if issuer_cert is not None:
        issuer_ski = issuer_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
            critical=False,
        )
    return builder.sign(signing_key, hashes.SHA256())


def _build_leaf_cert(
    cn: str,
    leaf_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    *,
    not_before: dt.datetime,
    not_after: dt.datetime,
    is_ca: bool = False,
    digital_signature: bool = True,
    aki_override: bytes | None = None,
    serial: int | None = None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_make_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
    )
    if aki_override is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=aki_override,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
    else:
        issuer_ski = issuer_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _independent_c14n(xml: str, *, exclusive: bool) -> bytes:
    root = LET.fromstring(xml.encode("utf-8"))
    return LET.tostring(
        root.getroottree(),
        method="c14n",
        exclusive=exclusive,
        with_comments=False,
    )


def _build_signed_tsl_xml(
    *,
    ca_entries: list[tuple[str, x509.Certificate, dt.datetime]],
    signer_cert: x509.Certificate,
    signer_key: rsa.RSAPrivateKey,
    sequence_number: int = 99,
    issue_dt: dt.datetime,
    next_update_dt: dt.datetime,
    signing_dt: dt.datetime | None = None,
    tsp_uris: dict[str, str] | None = None,
    reference_c14n: str | None = "http://www.w3.org/2001/10/xml-exc-c14n#",
    signed_properties_c14n: str | None = "http://www.w3.org/2001/10/xml-exc-c14n#",
    signed_info_c14n: str = "http://www.w3.org/2001/10/xml-exc-c14n#",
    root_attributes: str = "",
    document_suffix: str = "",
) -> bytes:
    tsp_blocks: list[str] = []
    for ca_id, ca_cert, status_start in ca_entries:
        cert_b64 = base64.b64encode(ca_cert.public_bytes(Encoding.DER)).decode("ascii")
        start_iso = status_start.strftime("%Y-%m-%dT%H:%M:%SZ")
        tsp_blocks.append(
            f"""<tsl:TrustServiceProvider>
                <tsl:TSPInformation>
                    <tsl:TSPName><tsl:Name xml:lang="fr">Test CA {ca_id}</tsl:Name></tsl:TSPName>
                    <tsl:TSPTradeName><tsl:Name xml:lang="fr">{ca_id}</tsl:Name></tsl:TSPTradeName>
                    {f'<tsl:TSPInformationURI><tsl:URI xml:lang="fr">{tsp_uris[ca_id]}</tsl:URI></tsl:TSPInformationURI>' if tsp_uris and ca_id in tsp_uris else ""}
                </tsl:TSPInformation>
                <tsl:TSPServices>
                    <tsl:TSPService>
                        <tsl:ServiceInformation>
                            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/PKC</tsl:ServiceTypeIdentifier>
                            <tsl:ServiceDigitalIdentity>
                                <tsl:DigitalId>
                                    <tsl:X509Certificate>{cert_b64}</tsl:X509Certificate>
                                </tsl:DigitalId>
                            </tsl:ServiceDigitalIdentity>
                            <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/Svcstatus/inaccord</tsl:ServiceStatus>
                            <tsl:StatusStartingTime>{start_iso}</tsl:StatusStartingTime>
                        </tsl:ServiceInformation>
                    </tsl:TSPService>
                </tsl:TSPServices>
            </tsl:TrustServiceProvider>"""
        )

    issue_iso = issue_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    next_iso = next_update_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    signing_iso = (signing_dt or issue_dt).strftime("%Y-%m-%dT%H:%M:%SZ")

    unsigned_xml = (
        '<tsl:TrustServiceStatusList xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        'xmlns:tsl="http://uri.etsi.org/02231/v2#" '
        f'xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"{root_attributes}>'
        "<tsl:SchemeInformation>"
        f"<tsl:TSLSequenceNumber>{sequence_number}</tsl:TSLSequenceNumber>"
        f"<tsl:ListIssueDateTime>{issue_iso}</tsl:ListIssueDateTime>"
        f"<tsl:NextUpdate><tsl:dateTime>{next_iso}</tsl:dateTime></tsl:NextUpdate>"
        "</tsl:SchemeInformation>"
        "<tsl:TrustServiceProviderList>"
        + "".join(tsp_blocks)
        + "</tsl:TrustServiceProviderList>"
        "</tsl:TrustServiceStatusList>"
    )

    c14n_doc = _independent_c14n(
        unsigned_xml + document_suffix,
        exclusive=reference_c14n == "http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    doc_digest = base64.b64encode(hashlib.sha256(c14n_doc).digest()).decode("ascii")
    doc_transforms = (
        '<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        + (
            f'<ds:Transform Algorithm="{reference_c14n}"/>'
            if reference_c14n is not None
            else ""
        )
        + "</ds:Transforms>"
    )

    signed_props_xml = (
        '<xades:SignedProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        'xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xades-sig-1">'
        "<xades:SignedSignatureProperties>"
        f"<xades:SigningTime>{signing_iso}</xades:SigningTime>"
        "</xades:SignedSignatureProperties>"
        "</xades:SignedProperties>"
    )
    signed_props_for_digest = signed_props_xml
    if signed_properties_c14n != "http://www.w3.org/2001/10/xml-exc-c14n#":
        ancestor_attributes = (
            ' xmlns:tsl="http://uri.etsi.org/02231/v2#"' + root_attributes
        )
        signed_props_for_digest = signed_props_xml.replace(
            ">", ancestor_attributes + ">", 1
        )
    c14n_sp = _independent_c14n(
        signed_props_for_digest,
        exclusive=signed_properties_c14n == "http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    sp_digest = base64.b64encode(hashlib.sha256(c14n_sp).digest()).decode("ascii")
    sp_transforms = (
        "<ds:Transforms>"
        + (
            f'<ds:Transform Algorithm="{signed_properties_c14n}"/>'
            if signed_properties_c14n is not None
            else ""
        )
        + "</ds:Transforms>"
        if signed_properties_c14n is not None
        else ""
    )

    signed_info_xml = (
        '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f'<ds:CanonicalizationMethod Algorithm="{signed_info_c14n}"/>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        '<ds:Reference URI="">'
        f"{doc_transforms}"
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f"<ds:DigestValue>{doc_digest}</ds:DigestValue>"
        "</ds:Reference>"
        '<ds:Reference URI="#xades-sig-1">'
        f"{sp_transforms}"
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f"<ds:DigestValue>{sp_digest}</ds:DigestValue>"
        "</ds:Reference>"
        "</ds:SignedInfo>"
    )
    signed_info_for_signature = signed_info_xml
    if signed_info_c14n != "http://www.w3.org/2001/10/xml-exc-c14n#":
        ancestor_attributes = (
            ' xmlns:tsl="http://uri.etsi.org/02231/v2#"'
            ' xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"' + root_attributes
        )
        signed_info_for_signature = signed_info_xml.replace(
            ">", ancestor_attributes + ">", 1
        )
    c14n_si = _independent_c14n(
        signed_info_for_signature,
        exclusive=signed_info_c14n == "http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    sig_bytes = signer_key.sign(c14n_si, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    signer_b64 = base64.b64encode(signer_cert.public_bytes(Encoding.DER)).decode(
        "ascii"
    )

    sig_block = (
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig-1">'
        + signed_info_xml.replace(
            ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"', "", 1
        )
        + f"<ds:SignatureValue>{sig_b64}</ds:SignatureValue>"
        + f"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{signer_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
        + '<ds:Object><xades:QualifyingProperties Target="#sig-1">'
        + signed_props_xml.replace(
            ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"',
            "",
            1,
        )
        + "</xades:QualifyingProperties></ds:Object>"
        + "</ds:Signature>"
    )

    signed_xml = unsigned_xml.replace(
        "</tsl:TrustServiceStatusList>",
        sig_block + "</tsl:TrustServiceStatusList>",
    )
    return (signed_xml + document_suffix).encode("utf-8")


def _build_crl(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    *,
    last_update: dt.datetime,
    next_update: dt.datetime,
    revoked_entries: list[tuple[int, dt.datetime, x509.ReasonFlags | None]]
    | None = None,
    extra_extensions: list[x509.Extension] | None = None,
    revoked_entry_extensions: list[x509.Extension] | None = None,
) -> x509.CertificateRevocationList:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(last_update)
        .next_update(next_update)
    )
    for serial, rev_dt, reason in revoked_entries or []:
        rev_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(rev_dt)
        )
        if reason is not None:
            rev_builder = rev_builder.add_extension(
                x509.CRLReason(reason), critical=False
            )
        for extension in revoked_entry_extensions or []:
            rev_builder = rev_builder.add_extension(
                extension.value, critical=extension.critical
            )
        builder = builder.add_revoked_certificate(rev_builder.build())
    for extension in extra_extensions or []:
        builder = builder.add_extension(extension.value, critical=extension.critical)
    return builder.sign(ca_key, hashes.SHA256())


@pytest.fixture
def synthetic_pki():
    """PKI synthétique complète : Ancre ANTS -> Signataire TSL -> AC FR06 -> Feuille FPE2."""
    ants_root_key = _make_rsa_key()
    ants_root_cert = _build_ca_cert(
        "Autorité de Certification Services Applicatifs",
        ants_root_key,
        not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2035, 1, 1, tzinfo=dt.timezone.utc),
    )

    tsl_signer_key = _make_rsa_key()
    tsl_signer_cert = _build_leaf_cert(
        "TSL0",
        tsl_signer_key,
        ants_root_cert,
        ants_root_key,
        not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2035, 1, 1, tzinfo=dt.timezone.utc),
    )

    ca_key = _make_ec_key()
    ca_cert = _build_ca_cert(
        "FR06",
        ca_key,
        not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2032, 1, 1, tzinfo=dt.timezone.utc),
    )

    leaf_key = _make_ec_key()
    leaf_cert = _build_leaf_cert(
        "FPE2",
        leaf_key,
        ca_cert,
        ca_key,
        not_before=dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc),
        serial=1001,
    )

    tsl_bytes = _build_signed_tsl_xml(
        ca_entries=[("FR06", ca_cert, dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc))],
        signer_cert=tsl_signer_cert,
        signer_key=tsl_signer_key,
        sequence_number=42,
        issue_dt=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )

    crl = _build_crl(
        ca_cert,
        ca_key,
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )

    return {
        "ants_root_key": ants_root_key,
        "ants_root_cert": ants_root_cert,
        "tsl_signer_key": tsl_signer_key,
        "tsl_signer_cert": tsl_signer_cert,
        "ca_key": ca_key,
        "ca_cert": ca_cert,
        "leaf_key": leaf_key,
        "leaf_cert": leaf_cert,
        "tsl_bytes": tsl_bytes,
        "crl": crl,
    }


def test_zero_network_calls_at_import_and_decode(monkeypatch):
    """Critère 1 : zéro appel réseau à l'import et lors de decode_2d_doc()."""

    def _forbid_network(*args, **kwargs):
        raise AssertionError("Appel réseau interdit au runtime !")

    monkeypatch.setattr(urllib.request, "urlopen", _forbid_network)
    reset_default_key_resolver()

    resolver = get_default_key_resolver()
    assert resolver.tsl_sequence_number == 23

    doc = _build_signed_2ddoc(
        ca_id="FR00",
        cert_id="0001",
        issue_date=dt.date(2022, 7, 31),
        signature_date=dt.date(2022, 7, 31),
        private_key=_make_ec_key(),
    )
    decoded = decode_2d_doc(doc)
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.UNKNOWN_CA
    assert decoded.is_valid is False


def test_valid_full_pki_chain_verified(synthetic_pki):
    """Critère 2 : chaîne complète TSL signée -> AC -> Feuille -> 2D-Doc signé => VERIFIED."""
    resolver = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
        crls_by_ca={"FR06": [synthetic_pki["crl"]]},
    )

    raw_doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )

    decoded = decode_2d_doc(
        raw_doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )

    assert decoded.is_valid is True
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.VERIFIED
    assert decoded.verification.ca_id == "FR06"
    assert decoded.verification.cert_id == "FPE2"
    assert decoded.verification.reference_date == dt.date(2022, 6, 15)
    assert decoded.verification.tsl_sequence_number == 42
    assert decoded.verification.tsl_freshness == TrustListFreshness.FRESH


def test_self_signed_and_rogue_certificates_rejected(synthetic_pki):
    """Critère 3 : certificat auto-signé ou émis par une AC tierce rejeté."""
    ca_cert = synthetic_pki["ca_cert"]

    # 1) Certificat auto-signé avec CN=FPE2
    attacker_key = _make_ec_key()
    self_signed = _build_leaf_cert(
        "FPE2",
        attacker_key,
        _build_ca_cert(
            "FPE2",
            attacker_key,
            not_before=dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc),
            not_after=dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc),
        ),
        attacker_key,
        not_before=dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc),
    )

    with pytest.raises(UntrustedCertificateError):
        validate_leaf_against_ca(self_signed, ca_cert)

    # 2) Certificat émis par une AC tierce non autorisée avec CN=FPE2
    rogue_ca_key = _make_ec_key()
    rogue_ca_cert = _build_ca_cert(
        "FR06",
        rogue_ca_key,
        not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc),
    )
    rogue_leaf = _build_leaf_cert(
        "FPE2",
        attacker_key,
        rogue_ca_cert,
        rogue_ca_key,
        not_before=dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc),
    )

    resolver = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
    )
    with pytest.raises(UntrustedCertificateError):
        resolver.add_leaf("FR06", rogue_leaf)

    # 3) Si injecté manuellement en mémoire dans leaf_index, la résolution échoue en UNTRUSTED_CERTIFICATE
    tampered_resolver = KeyResolver(
        ca_records=resolver._ca_records,
        leaf_index={("FR06", "FPE2"): rogue_leaf},
        tsl_metadata=resolver._tsl_metadata,
    )
    rogue_doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=attacker_key,
    )
    decoded = decode_2d_doc(
        rogue_doc,
        key_resolver=tampered_resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert decoded.is_valid is False
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.UNTRUSTED_CERTIFICATE


def test_leaf_x509_constraints_enforced(synthetic_pki):
    """Validation stricte BasicConstraints, KeyUsage, AKI/SKI et CN 4 caractères."""
    ca_cert = synthetic_pki["ca_cert"]
    ca_key = synthetic_pki["ca_key"]
    key = _make_ec_key()
    nb = dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc)
    na = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)

    # BasicConstraints CA=True interdit sur feuille
    ca_flagged_leaf = _build_leaf_cert(
        "ABCD", key, ca_cert, ca_key, not_before=nb, not_after=na, is_ca=True
    )
    with pytest.raises(UntrustedCertificateError):
        validate_leaf_against_ca(ca_flagged_leaf, ca_cert)

    # KeyUsage sans digitalSignature interdit
    no_sig_leaf = _build_leaf_cert(
        "ABCD",
        key,
        ca_cert,
        ca_key,
        not_before=nb,
        not_after=na,
        digital_signature=False,
    )
    with pytest.raises(UntrustedCertificateError):
        validate_leaf_against_ca(no_sig_leaf, ca_cert)

    # AKI discordant
    bad_aki_leaf = _build_leaf_cert(
        "ABCD",
        key,
        ca_cert,
        ca_key,
        not_before=nb,
        not_after=na,
        aki_override=b"\x00" * 20,
    )
    with pytest.raises(UntrustedCertificateError):
        validate_leaf_against_ca(bad_aki_leaf, ca_cert)

    # CN non conforme (!= 4 chars alphanumériques)
    bad_cn_leaf = _build_leaf_cert(
        "LONG_COMMON_NAME", key, ca_cert, ca_key, not_before=nb, not_after=na
    )
    with pytest.raises(UntrustedCertificateError):
        validate_leaf_against_ca(bad_cn_leaf, ca_cert)


def test_single_cert_fallback_removed_and_unknown_ca(synthetic_pki):
    """Critères 4 & 5 : pas de fallback sur certificat unique ; ca_id inconnu / FR00 -> UNKNOWN_CA."""
    resolver = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
    )

    # Certificat unique sous FR06 -> ZZZZ doit lever UnknownCertificateError
    with pytest.raises(UnknownCertificateError):
        resolver.resolve("FR06", "ZZZZ")

    with pytest.raises(UnknownCAError):
        resolver.resolve("FR00", "0001")

    doc_unknown_cert = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="ZZZZ",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )
    res_cert = decode_2d_doc(
        doc_unknown_cert,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert res_cert.is_valid is False
    assert res_cert.verification is not None
    assert res_cert.verification.status == VerificationStatus.UNKNOWN_CERT

    doc_fr00 = _build_signed_2ddoc(
        ca_id="FR00",
        cert_id="0001",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )
    res_ca = decode_2d_doc(
        doc_fr00,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert res_ca.is_valid is False
    assert res_ca.verification is not None
    assert res_ca.verification.status == VerificationStatus.UNKNOWN_CA


def test_tampered_payload_or_signature_and_missing_signature(synthetic_pki):
    """Critères 6 & 7 : payload/signature altérés -> SIGNATURE_INVALID ; absente -> SIGNATURE_MISSING."""
    resolver = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
        crls_by_ca={"FR06": [synthetic_pki["crl"]]},
    )

    valid_doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )

    # 1) Altération du payload
    tampered_payload_doc = valid_doc.replace("PARIS", "LYON!")
    dec_payload = decode_2d_doc(
        tampered_payload_doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert dec_payload.is_valid is False
    assert dec_payload.verification is not None
    assert dec_payload.verification.status == VerificationStatus.SIGNATURE_INVALID

    # 2) Altération d'un caractère dans la signature
    left, sig_b32 = valid_doc.split("\x1f", 1)
    flipped_char = "B" if sig_b32[0] != "B" else "C"
    tampered_sig_doc = f"{left}\x1f{flipped_char}{sig_b32[1:]}"
    dec_sig = decode_2d_doc(
        tampered_sig_doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert dec_sig.is_valid is False
    assert dec_sig.verification is not None
    assert dec_sig.verification.status == VerificationStatus.SIGNATURE_INVALID

    # 3) Signature absente
    unsigned_doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=None,
    )
    dec_unsigned = decode_2d_doc(
        unsigned_doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert dec_unsigned.is_valid is False
    assert dec_unsigned.verification is not None
    assert dec_unsigned.verification.status == VerificationStatus.SIGNATURE_MISSING


def test_validity_at_signing_date(synthetic_pki):
    """Critère 8 : validité à la date de signature (expiré aujourd'hui OK, hors période KO, FFFF expiré KO)."""
    resolver = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
        crls_by_ca={"FR06": [synthetic_pki["crl"]]},
    )

    # Feuille valide [2021-01-01 .. 2024-01-01], évaluation en 2026-11-17
    # 1) Signé en 2022 -> VALIDE
    doc_2022 = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )
    res_2022 = decode_2d_doc(
        doc_2022, key_resolver=resolver, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_2022.is_valid is True
    assert res_2022.verification is not None
    assert res_2022.verification.status == VerificationStatus.VERIFIED

    # 2) Signé en 2025 -> hors fenêtre feuille -> CERT_NOT_VALID_AT_SIGNING
    doc_2025 = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2025, 2, 1),
        signature_date=dt.date(2025, 2, 1),
        private_key=synthetic_pki["leaf_key"],
    )
    res_2025 = decode_2d_doc(
        doc_2025, key_resolver=resolver, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_2025.is_valid is False
    assert res_2025.verification is not None
    assert res_2025.verification.status == VerificationStatus.CERT_NOT_VALID_AT_SIGNING

    # 3) Dates FFFF (absentes) et certificat expiré à evaluation_date (2026) -> CERT_NOT_VALID_AT_SIGNING
    doc_ffff = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=None,
        signature_date=None,
        private_key=synthetic_pki["leaf_key"],
    )
    res_ffff = decode_2d_doc(
        doc_ffff, key_resolver=resolver, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_ffff.is_valid is False
    assert res_ffff.verification is not None
    assert res_ffff.verification.status == VerificationStatus.CERT_NOT_VALID_AT_SIGNING

    # 4) signature_date absente (FFFF) mais issue_date en 2022 -> fallback issue_date -> VERIFIED
    doc_issue_only = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=None,
        private_key=synthetic_pki["leaf_key"],
    )
    res_issue = decode_2d_doc(
        doc_issue_only, key_resolver=resolver, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_issue.is_valid is True
    assert res_issue.verification is not None
    assert res_issue.verification.status == VerificationStatus.VERIFIED


def test_crl_revocation_and_crl_signature_verification(synthetic_pki):
    """Critère 9 : CRL signée, révocation après/à la date vs avant révocation vs compromission."""
    leaf_serial = synthetic_pki["leaf_cert"].serial_number
    rev_dt = dt.datetime(2023, 6, 1, 12, 0, 0, tzinfo=dt.timezone.utc)

    # CRL avec cessation_of_operation
    crl_cessation = _build_crl(
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
        revoked_entries=[
            (leaf_serial, rev_dt, x509.ReasonFlags.cessation_of_operation)
        ],
    )
    resolver_cess = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
        crls_by_ca={"FR06": [crl_cessation]},
    )

    # Document signé APRÈS révocation -> CERT_REVOKED
    doc_after = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2023, 7, 1),
        signature_date=dt.date(2023, 7, 1),
        private_key=synthetic_pki["leaf_key"],
    )
    res_after = decode_2d_doc(
        doc_after, key_resolver=resolver_cess, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_after.is_valid is False
    assert res_after.verification is not None
    assert res_after.verification.status == VerificationStatus.CERT_REVOKED

    # Document signé AVANT révocation non-compromission -> VERIFIED
    doc_before = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2023, 5, 1),
        signature_date=dt.date(2023, 5, 1),
        private_key=synthetic_pki["leaf_key"],
    )
    res_before = decode_2d_doc(
        doc_before, key_resolver=resolver_cess, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_before.is_valid is True
    assert res_before.verification is not None
    assert res_before.verification.status == VerificationStatus.VERIFIED

    # CRL avec key_compromise -> même AVANT la date de révocation => CERT_REVOKED
    crl_compromise = _build_crl(
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
        revoked_entries=[(leaf_serial, rev_dt, x509.ReasonFlags.key_compromise)],
    )
    resolver_comp = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
        crls_by_ca={"FR06": [crl_compromise]},
    )
    res_comp = decode_2d_doc(
        doc_before, key_resolver=resolver_comp, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_comp.is_valid is False
    assert res_comp.verification is not None
    assert res_comp.verification.status == VerificationStatus.CERT_REVOKED

    # CRL signée par un tiers non autorisé -> TrustSignatureError
    rogue_crl = _build_crl(
        synthetic_pki["ca_cert"],
        _make_ec_key(),
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )
    with pytest.raises(TrustSignatureError):
        resolver_cess.add_crl("FR06", rogue_crl)


def test_tsl_expiry_tampering_and_xml_security(synthetic_pki):
    """Critère 10 : TSL périmée (strict vs non-strict), TSL altérée, XML DOCTYPE/XSW."""
    crl = _build_crl(
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2028, 5, 1, tzinfo=dt.timezone.utc),
    )
    resolver = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
        crls_by_ca={"FR06": [crl]},
    )
    raw_doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )

    # NextUpdate = 2027-05-01 ; évaluation en 2027-05-02
    res_strict = decode_2d_doc(
        raw_doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2027, 5, 2),
        strict_tsl_freshness=True,
    )
    assert res_strict.is_valid is False
    assert res_strict.verification is not None
    assert res_strict.verification.status == VerificationStatus.TRUST_LIST_EXPIRED
    assert res_strict.verification.tsl_freshness == TrustListFreshness.STALE

    res_lenient = decode_2d_doc(
        raw_doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2027, 5, 2),
        strict_tsl_freshness=False,
    )
    assert res_lenient.is_valid is True
    assert res_lenient.verification is not None
    assert res_lenient.verification.status == VerificationStatus.VERIFIED
    assert res_lenient.verification.tsl_freshness == TrustListFreshness.STALE

    # Altération de NextUpdate dans la TSL sans re-signer -> TrustSignatureError
    tampered_tsl = synthetic_pki["tsl_bytes"].replace(
        b"2027-05-01T00:00:00Z", b"2099-05-01T00:00:00Z"
    )
    with pytest.raises(TrustSignatureError):
        verify_tsl_xml_signature(tampered_tsl, synthetic_pki["ants_root_cert"])

    # Rejet DOCTYPE / ENTITY (XXE)
    xxe_tsl = (
        b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]>'
        + synthetic_pki["tsl_bytes"]
    )
    with pytest.raises(TrustSignatureError):
        verify_tsl_xml_signature(xxe_tsl, synthetic_pki["ants_root_cert"])

    # Rejet XML Signature Wrapping (double élément ds:Signature)
    dom = minidom.parseString(synthetic_pki["tsl_bytes"].decode("utf-8"))
    assert dom.documentElement is not None
    sig_clone = dom.documentElement.getElementsByTagNameNS(
        "http://www.w3.org/2000/09/xmldsig#", "Signature"
    )[0].cloneNode(deep=True)
    assert isinstance(sig_clone, minidom.Element)
    dom.documentElement.appendChild(sig_clone)
    with pytest.raises(TrustSignatureError):
        verify_tsl_xml_signature(
            dom.toxml().encode("utf-8"), synthetic_pki["ants_root_cert"]
        )


def test_resolver_unavailable_does_not_crash(monkeypatch, tmp_path: Path):
    """Critère 11 : magasin de confiance manquant/corrompu -> RESOLVER_UNAVAILABLE sans crash."""
    bad_dir = tmp_path / "missing_store"
    monkeypatch.setenv(ENV_TRUST_STORE_DIR, str(bad_dir))
    reset_default_key_resolver()

    try:
        doc = _build_signed_2ddoc(
            ca_id="FR06",
            cert_id="FPE2",
            issue_date=dt.date(2022, 6, 15),
            signature_date=dt.date(2022, 6, 15),
            private_key=_make_ec_key(),
        )
        decoded = decode_2d_doc(doc)
        assert decoded.is_valid is False
        assert decoded.verification is not None
        assert decoded.verification.status == VerificationStatus.RESOLVER_UNAVAILABLE
    finally:
        monkeypatch.delenv(ENV_TRUST_STORE_DIR, raising=False)
        reset_default_key_resolver()

    # Aussi avec verify(None) directement
    decoded_manual = decode_2d_doc(doc, key_resolver=None)
    res = decoded_manual.verify(None)
    assert res.status == VerificationStatus.RESOLVER_UNAVAILABLE
    assert decoded_manual.is_valid is False


def test_embedded_snapshot_loads_offline_and_enforces_revocations(monkeypatch):
    """Critère 12 : le snapshot embarqué réel (TSL v23, 7 AC, 230 feuilles, 7 CRLs) se charge sans réseau et sans warning."""

    def _forbid_network(*args, **kwargs):
        raise AssertionError("Aucun appel réseau ne doit être effectué !")

    monkeypatch.setattr(urllib.request, "urlopen", _forbid_network)
    reset_default_key_resolver()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        resolver = get_default_key_resolver()

    key_resolver_warnings = [
        w for w in caught if "Attribute's length must be" in str(w.message)
    ]
    assert key_resolver_warnings == []

    assert resolver.tsl_sequence_number == 23
    assert resolver.tsl_next_update == dt.datetime(
        2027, 5, 11, 14, 0, 0, tzinfo=dt.timezone.utc
    )
    assert resolver.ca_ids == {"FR01", "FR03", "FR04", "FR05", "FR06", "FR07", "FR09"}
    assert "FR00" not in resolver.ca_ids

    total_leaves = sum(len(resolver.available_cert_ids(ca)) for ca in resolver.ca_ids)
    assert total_leaves == 230

    # Vérifie que les certificats notoirement révoqués (ex: FR04/FPE6, FR03/0000) sont bien détectés révoqués
    fpe6_cert = resolver._leaf_index[("FR04", "FPE6")]
    with pytest.raises(Exception) as exc_info:
        check_certificate_revocation(
            fpe6_cert,
            resolver._crls_by_ca["FR04"],
            dt.date(2024, 1, 15),
            dt.date(2026, 11, 17),
        )
    assert "révoqué" in str(exc_info.value)

    test_0000_cert = resolver._leaf_index[("FR03", "0000")]
    with pytest.raises(Exception) as exc_info_2:
        check_certificate_revocation(
            test_0000_cert,
            resolver._crls_by_ca["FR03"],
            dt.date(2016, 1, 1),
            dt.date(2026, 11, 17),
        )
    assert "révoqué" in str(exc_info_2.value)


def test_tsl_xsw_unsigned_object_rejected(synthetic_pki):
    """SEC-01 : injection XML Signature Wrapping dans <ds:Object> / <ds:KeyInfo> rejetée."""
    evil_ca_key = _make_ec_key()
    evil_ca_cert = _build_ca_cert(
        "FR99",
        evil_ca_key,
        not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2032, 1, 1, tzinfo=dt.timezone.utc),
    )
    evil_b64 = base64.b64encode(evil_ca_cert.public_bytes(Encoding.DER)).decode("ascii")
    injected_tsp = (
        "<ds:Object>"
        '<tsl:TrustServiceProvider xmlns:tsl="http://uri.etsi.org/02231/v2#">'
        "<tsl:TSPInformation>"
        '<tsl:TSPName><tsl:Name xml:lang="fr">Evil CA</tsl:Name></tsl:TSPName>'
        '<tsl:TSPTradeName><tsl:Name xml:lang="fr">FR99</tsl:Name></tsl:TSPTradeName>'
        "</tsl:TSPInformation>"
        "<tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation>"
        "<tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/PKC</tsl:ServiceTypeIdentifier>"
        "<tsl:ServiceDigitalIdentity><tsl:DigitalId>"
        f"<tsl:X509Certificate>{evil_b64}</tsl:X509Certificate>"
        "</tsl:DigitalId></tsl:ServiceDigitalIdentity>"
        "<tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/Svcstatus/inaccord</tsl:ServiceStatus>"
        "<tsl:StatusStartingTime>2020-01-01T00:00:00Z</tsl:StatusStartingTime>"
        "</tsl:ServiceInformation></tsl:TSPService></tsl:TSPServices>"
        "</tsl:TrustServiceProvider>"
        "</ds:Object>"
    ).encode("utf-8")

    evil_tsl = synthetic_pki["tsl_bytes"].replace(
        b"</ds:Signature>", injected_tsp + b"</ds:Signature>"
    )

    with pytest.raises(TrustSignatureError):
        KeyResolver.from_tsl(
            evil_tsl,
            root_ca_cert=synthetic_pki["ants_root_cert"],
            verify_tsl_signature=True,
        )

    # Même en appelant _parse_tsl_bytes directement, FR99 n'est jamais extraite
    recs, _, _ = _parse_tsl_bytes(evil_tsl)
    assert all(r.ca_id != "FR99" for r in recs)


def test_fetch_bytes_rejects_non_http_schemes_and_oversized_payloads(monkeypatch):
    """SEC-02 : validation des schémas URL, restriction du fallback HTTP et borne 10 Mo."""
    html = (
        b'<a href="file:///etc/passwd.pem">bad1</a>'
        b'<a href="ftp://evil.example/a.cer">bad2</a>'
        b'<a href="javascript:alert(1).der">bad3</a>'
        b'<a href="https://good.example/cert.der">ok1</a>'
        b'<a href="sub/leaf.pem">ok2</a>'
    )
    links = _extract_links(html, "https://good.example/dir/index.html")
    assert links == [
        "https://good.example/cert.der",
        "https://good.example/dir/sub/leaf.pem",
    ]

    called_urls: list[str] = []

    class _FakeResp:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self, n: int = -1) -> bytes:
            return self._payload if n < 0 else self._payload[:n]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def _fake_urlopen(req, timeout=10):
        called_urls.append(req.full_url)
        if req.full_url.startswith("https://sp.ants.gouv.fr/"):
            raise OSError("TLS internal CA")
        if req.full_url.startswith("https://evil-ants.gouv.fr/"):
            raise OSError("TLS error")
        if "oversized" in req.full_url:
            return _FakeResp(b"x" * (_MAX_FETCH_BYTES + 5))
        return _FakeResp(b"ok")

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    # Rejet file:// et ftp:// sans aucun appel urlopen
    assert _fetch_bytes("file:///etc/passwd") is None
    assert _fetch_bytes("ftp://example.com/file.der") is None
    assert called_urls == []

    # Fallback HTTP autorisé uniquement pour sp.ants.gouv.fr exact
    assert _fetch_bytes("https://sp.ants.gouv.fr/cev/FR09_cert.der") == b"ok"
    assert called_urls == [
        "https://sp.ants.gouv.fr/cev/FR09_cert.der",
        "http://sp.ants.gouv.fr/cev/FR09_cert.der",
    ]

    called_urls.clear()
    assert _fetch_bytes("https://evil-ants.gouv.fr/cert.der") is None
    assert called_urls == ["https://evil-ants.gouv.fr/cert.der"]

    # Rejet payload dépassant _MAX_FETCH_BYTES
    assert _fetch_bytes("https://good.example/oversized.der") is None


def test_sync_trust_store_atomic_fail_closed(
    monkeypatch, tmp_path: Path, synthetic_pki
):
    """AC-10 : sync_trust_store met à jour atomiquement et n'écrase pas en cas d'échec."""
    anchor_pem = synthetic_pki["ants_root_cert"].public_bytes(Encoding.PEM)
    (tmp_path / "ants_tsl_root_ca.pem").write_bytes(anchor_pem)

    ca_cert = synthetic_pki["ca_cert"]
    leaf_der = synthetic_pki["leaf_cert"].public_bytes(Encoding.DER)
    crl_der = synthetic_pki["crl"].public_bytes(Encoding.DER)

    tsl_v42 = _build_signed_tsl_xml(
        ca_entries=[("FR06", ca_cert, dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc))],
        signer_cert=synthetic_pki["tsl_signer_cert"],
        signer_key=synthetic_pki["tsl_signer_key"],
        sequence_number=42,
        issue_dt=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )
    tsl_v43 = _build_signed_tsl_xml(
        ca_entries=[("FR06", ca_cert, dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc))],
        signer_cert=synthetic_pki["tsl_signer_cert"],
        signer_key=synthetic_pki["tsl_signer_key"],
        sequence_number=43,
        issue_dt=dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 6, 1, tzinfo=dt.timezone.utc),
        tsp_uris={"FR06": "https://ca.example/fr06.der"},
    )

    # Initialise un magasin v42 existant
    (tmp_path / "tsl_signed.xml").write_bytes(tsl_v42)
    (tmp_path / "trusted_leaves").mkdir()
    (tmp_path / "trusted_leaves" / "FR06.pem").write_bytes(
        synthetic_pki["leaf_cert"].public_bytes(Encoding.PEM)
    )
    (tmp_path / "crls").mkdir()
    (tmp_path / "crls" / "FR06.crl").write_bytes(crl_der)

    def _mock_fetch_ok(url: str, timeout: int = 15) -> bytes | None:
        if url == "https://tsl.example/tsl.xml":
            return tsl_v43
        if url == "https://ca.example/fr06.der":
            return leaf_der
        if url == "https://ca.example/fr06.crl":
            return crl_der
        return None

    monkeypatch.setattr(sync_mod, "_fetch_bytes", _mock_fetch_ok)
    monkeypatch.setattr(
        sync_mod,
        "extract_crl_urls_from_certs",
        lambda certs: ["https://ca.example/fr06.crl"],
    )

    # 1) Synchronisation nominale vers v43
    synced = sync_mod.sync_trust_store(
        output_dir=tmp_path,
        tsl_url="https://tsl.example/tsl.xml",
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert synced.tsl_sequence_number == 43
    assert synced.available_cert_ids("FR06") == {"FPE2"}

    # 2) Échec (TSL altérée) -> fail-closed, le magasin v43 existant reste intact
    tampered_v44 = tsl_v43.replace(b">43<", b">44<")
    monkeypatch.setattr(
        sync_mod,
        "_fetch_bytes",
        lambda url, timeout=15: tampered_v44 if "tsl.xml" in url else None,
    )
    with pytest.raises(TrustSignatureError):
        sync_mod.sync_trust_store(
            output_dir=tmp_path, tsl_url="https://tsl.example/tsl.xml"
        )

    reloaded = KeyResolver.from_trust_store(tmp_path)
    assert reloaded.tsl_sequence_number == 43


def test_certificate_rotation_same_cert_id_preserves_historical_verification(
    synthetic_pki,
):
    """AC-5 / QUAL-02 : la rotation sur un même (ca_id, cert_id) préserve la vérification historique et en recouvrement."""
    old_key = synthetic_pki["leaf_key"]
    old_cert = _build_leaf_cert(
        "FPE2",
        old_key,
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        not_before=dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2024, 6, 1, tzinfo=dt.timezone.utc),
        serial=2001,
    )

    new_key = _make_ec_key()
    new_cert = _build_leaf_cert(
        "FPE2",
        new_key,
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        not_before=dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc),
        serial=2002,
    )

    resolver = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [old_cert, new_cert]},
        crls_by_ca={"FR06": [synthetic_pki["crl"]]},
    )

    # _leaf_index reste rétrocompatible et pointe vers le plus récent
    assert resolver._leaf_index[("FR06", "FPE2")].serial_number == 2002

    # 1) Document signé en 2022 avec l'ancien certificat -> VERIFIED
    doc_2022 = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=old_key,
    )
    res_2022 = decode_2d_doc(
        doc_2022, key_resolver=resolver, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_2022.is_valid is True
    assert res_2022.verification is not None
    assert res_2022.verification.status == VerificationStatus.VERIFIED

    # 2) Document signé en 2025 avec le nouveau certificat -> VERIFIED
    doc_2025 = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2025, 6, 15),
        signature_date=dt.date(2025, 6, 15),
        private_key=new_key,
    )
    res_2025 = decode_2d_doc(
        doc_2025, key_resolver=resolver, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_2025.is_valid is True
    assert res_2025.verification is not None
    assert res_2025.verification.status == VerificationStatus.VERIFIED

    # 3) Période de recouvrement (2024-03-01) : ancien ET nouveau signataires acceptés
    doc_overlap_old = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2024, 3, 1),
        signature_date=dt.date(2024, 3, 1),
        private_key=old_key,
    )
    res_overlap_old = decode_2d_doc(
        doc_overlap_old, key_resolver=resolver, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_overlap_old.is_valid is True

    doc_overlap_new = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2024, 3, 1),
        signature_date=dt.date(2024, 3, 1),
        private_key=new_key,
    )
    res_overlap_new = decode_2d_doc(
        doc_overlap_new, key_resolver=resolver, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_overlap_new.is_valid is True

    # 4) Si le nouveau certificat est révoqué (2025), le document historique de 2022 reste VERIFIED
    crl_new_revoked = _build_crl(
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
        revoked_entries=[
            (
                2002,
                dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc),
                x509.ReasonFlags.key_compromise,
            )
        ],
    )
    resolver_rev = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [old_cert, new_cert]},
        crls_by_ca={"FR06": [crl_new_revoked]},
    )
    res_hist_with_new_rev = decode_2d_doc(
        doc_2022, key_resolver=resolver_rev, evaluation_date=dt.date(2026, 11, 17)
    )
    assert res_hist_with_new_rev.is_valid is True


def test_from_tsl_accepts_xml_string_without_oserror(synthetic_pki):
    """QUAL-01 : KeyResolver.from_tsl() accepte une str XML (>255 octets) sans OSError ENAMETOOLONG."""
    xml_str = synthetic_pki["tsl_bytes"].decode("utf-8")
    resolver = KeyResolver.from_tsl(
        xml_str,
        root_ca_cert=synthetic_pki["ants_root_cert"],
    )
    assert resolver.tsl_sequence_number == 42
    assert "FR06" in resolver.ca_ids

    real_tsl_path = Path("src/fr_2ddoc_parser/crypto/keys/tsl_signed.xml")
    real_resolver = KeyResolver.from_tsl(real_tsl_path.read_text(encoding="utf-8"))
    assert real_resolver.tsl_sequence_number == 23


def test_embedded_leaves_before_tsl_status_start_and_private_key_usage_period():
    """QUAL-03 : les 6 certificats antérieurs au StatusStartingTime passent et PrivateKeyUsagePeriod est appliqué."""
    reset_default_key_resolver()
    resolver = KeyResolver.from_trust_store(require_crls=False)

    early_cases = [
        ("FR01", "SFR0", dt.date(2012, 6, 28)),
        ("FR01", "SFR1", dt.date(2012, 8, 14)),
        ("FR04", "0000", dt.date(2015, 7, 10)),
        ("FR04", "ULR1", dt.date(2015, 11, 20)),
        ("FR04", "IN00", dt.date(2015, 12, 10)),
        ("FR05", "0001", dt.date(2021, 3, 10)),
    ]
    for ca_id, cert_id, ref_date in early_cases:
        ctx = resolver.resolve_for_verification(
            ca_id,
            cert_id,
            reference_date=ref_date,
            evaluation_date=dt.date(2026, 11, 17),
        )
        assert ctx.ca_id == ca_id
        assert ctx.cert_id == cert_id

    # FR05/0001 : certificat valide jusqu'en 2024-03-08, mais PrivateKeyUsagePeriod s'arrête au 2021-06-08
    with pytest.raises(CertificateValidityError):
        resolver.resolve_for_verification(
            "FR05",
            "0001",
            reference_date=dt.date(2022, 1, 1),
            evaluation_date=dt.date(2026, 11, 17),
        )

    doc_after_pkup = _build_signed_2ddoc(
        ca_id="FR05",
        cert_id="0001",
        issue_date=dt.date(2022, 1, 1),
        signature_date=dt.date(2022, 1, 1),
        private_key=_make_ec_key(),
    )
    decoded = decode_2d_doc(
        doc_after_pkup,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert decoded.is_valid is False
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.CERT_NOT_VALID_AT_SIGNING


def test_strict_tsl_freshness_fails_closed_when_next_update_missing_or_direct_call(
    synthetic_pki,
):
    """SEC-01 / QUAL-05 : TSL sans NextUpdate -> TRUST_LIST_EXPIRED en strict ; evaluation_date propagé."""
    base_resolver = KeyResolver.from_tsl(
        synthetic_pki["tsl_bytes"],
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
        crls_by_ca={"FR06": [synthetic_pki["crl"]]},
    )

    # 1) NextUpdate absent (TrustListFreshness.UNKNOWN) doit échouer en strict_tsl_freshness=True
    resolver_unknown = KeyResolver(
        ca_records=base_resolver._ca_records,
        leaf_index=base_resolver._leaf_index,
        crls_by_ca=base_resolver._crls_by_ca,
        tsl_metadata=TslMetadata(
            sequence_number=42,
            issue_date=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
            next_update=None,
            signer_cn="TSL0",
        ),
    )
    doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )
    res_unknown_strict = decode_2d_doc(
        doc, key_resolver=resolver_unknown, strict_tsl_freshness=True
    )
    assert res_unknown_strict.is_valid is False
    assert res_unknown_strict.verification is not None
    assert (
        res_unknown_strict.verification.status == VerificationStatus.TRUST_LIST_EXPIRED
    )
    assert res_unknown_strict.verification.tsl_freshness == TrustListFreshness.UNKNOWN

    # En mode non-strict, la vérification continue
    res_unknown_lenient = decode_2d_doc(
        doc, key_resolver=resolver_unknown, strict_tsl_freshness=False
    )
    assert res_unknown_lenient.is_valid is True

    # 2) Appel direct resolve_for_verification(..., evaluation_date=2028-01-01) sans tsl_eval_date
    with pytest.raises(TrustListExpiredError):
        base_resolver.resolve_for_verification(
            "FR06",
            "FPE2",
            reference_date=dt.date(2022, 6, 15),
            evaluation_date=dt.date(2028, 1, 1),
        )

    # 3) TSL XML sans NextUpdate ou avec ListIssueDateTime > NextUpdate rejetée par verify_tsl_xml_signature
    no_next_tsl = re_sub_tsl_tag(
        synthetic_pki["tsl_bytes"],
        b"<tsl:NextUpdate><tsl:dateTime>2027-05-01T00:00:00Z</tsl:dateTime></tsl:NextUpdate>",
        b"",
    )
    with pytest.raises(TrustSignatureError):
        verify_tsl_xml_signature(no_next_tsl, synthetic_pki["ants_root_cert"])


def re_sub_tsl_tag(tsl_bytes: bytes, old: bytes, new: bytes) -> bytes:
    assert old in tsl_bytes
    return tsl_bytes.replace(old, new, 1)


def test_from_trust_store_fails_closed_when_crls_missing(tmp_path: Path, synthetic_pki):
    """SEC-03 : from_trust_store et sync_trust_store échouent (fail-closed) si les CRLs manquent."""
    (tmp_path / "ants_tsl_root_ca.pem").write_bytes(
        synthetic_pki["ants_root_cert"].public_bytes(Encoding.PEM)
    )
    (tmp_path / "tsl_signed.xml").write_bytes(synthetic_pki["tsl_bytes"])
    (tmp_path / "trusted_leaves").mkdir()
    (tmp_path / "trusted_leaves" / "FR06.pem").write_bytes(
        synthetic_pki["leaf_cert"].public_bytes(Encoding.PEM)
    )

    # 1) Dossier crls/ absent -> ResolverUnavailableError
    with pytest.raises(ResolverUnavailableError):
        KeyResolver.from_trust_store(tmp_path)

    # 2) Dossier crls/ vide -> ResolverUnavailableError
    (tmp_path / "crls").mkdir()
    with pytest.raises(ResolverUnavailableError):
        KeyResolver.from_trust_store(tmp_path)

    # 3) Mode explicite require_crls=False autorisé si demandé
    resolver_no_crl = KeyResolver.from_trust_store(tmp_path, require_crls=False)
    assert "FR06" in resolver_no_crl.ca_ids

    # 4) sync_trust_store échoue en fail-closed si la CRL d'une AC active est injoignable
    tsl_with_uri = _build_signed_tsl_xml(
        ca_entries=[
            (
                "FR06",
                synthetic_pki["ca_cert"],
                dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
            )
        ],
        signer_cert=synthetic_pki["tsl_signer_cert"],
        signer_key=synthetic_pki["tsl_signer_key"],
        sequence_number=50,
        issue_dt=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
        tsp_uris={"FR06": "https://ca.example/fr06.der"},
    )
    leaf_der = synthetic_pki["leaf_cert"].public_bytes(Encoding.DER)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            sync_mod,
            "_fetch_bytes",
            lambda url, timeout=15: (
                tsl_with_uri
                if "tsl.xml" in url
                else (leaf_der if "fr06.der" in url else None)
            ),
        )
        mp.setattr(
            sync_mod,
            "extract_crl_urls_from_certs",
            lambda certs: ["https://ca.example/fr06.crl"],
        )
        with pytest.raises(ResolverUnavailableError):
            sync_mod.sync_trust_store(
                output_dir=tmp_path, tsl_url="https://tsl.example/tsl.xml"
            )


def test_ca_and_tsl_signer_x509_constraints_sec02(synthetic_pki):
    """SEC-02 : contraintes CA (BasicConstraints, keyCertSign, cRLSign) et signataire TSL (KeyUsage, AKI/SKI, dates)."""
    # 1) AC sans BasicConstraints ca=True ni keyCertSign / cRLSign
    fake_ca_key = _make_ec_key()
    nb = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    na = dt.datetime(2032, 1, 1, tzinfo=dt.timezone.utc)

    ca_no_bc = (
        x509.CertificateBuilder()
        .subject_name(_make_name("FR06"))
        .issuer_name(_make_name("FR06"))
        .public_key(fake_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(fake_ca_key.public_key()),
            critical=False,
        )
        .sign(fake_ca_key, hashes.SHA256())
    )
    leaf_under_fake = _build_leaf_cert(
        "FPE2",
        _make_ec_key(),
        ca_no_bc,
        fake_ca_key,
        not_before=dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc),
    )
    with pytest.raises(UntrustedCertificateError):
        validate_leaf_against_ca(leaf_under_fake, ca_no_bc)

    crl_under_fake = _build_crl(
        ca_no_bc,
        fake_ca_key,
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )
    with pytest.raises(TrustSignatureError):
        validate_crl_against_ca(crl_under_fake, ca_no_bc)

    # 2) AC avec ca=True mais sans keyCertSign ni cRLSign
    ca_no_ku = (
        x509.CertificateBuilder()
        .subject_name(_make_name("FR06"))
        .issuer_name(_make_name("FR06"))
        .public_key(fake_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(fake_ca_key.public_key()),
            critical=False,
        )
        .sign(fake_ca_key, hashes.SHA256())
    )
    leaf_no_ku_ca = _build_leaf_cert(
        "FPE2",
        _make_ec_key(),
        ca_no_ku,
        fake_ca_key,
        not_before=dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc),
    )
    with pytest.raises(UntrustedCertificateError):
        validate_leaf_against_ca(leaf_no_ku_ca, ca_no_ku)

    crl_no_ku_ca = _build_crl(
        ca_no_ku,
        fake_ca_key,
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )
    with pytest.raises(TrustSignatureError):
        validate_crl_against_ca(crl_no_ku_ca, ca_no_ku)

    # 3) Signataire TSL sans KeyUsage.digitalSignature -> TrustSignatureError
    tsl_signer_no_ku_key = _make_rsa_key()
    tsl_signer_no_ku = _build_leaf_cert(
        "TSL1",
        tsl_signer_no_ku_key,
        synthetic_pki["ants_root_cert"],
        synthetic_pki["ants_root_key"],
        not_before=nb,
        not_after=na,
        digital_signature=False,
    )
    tsl_bad_signer = _build_signed_tsl_xml(
        ca_entries=[("FR06", synthetic_pki["ca_cert"], nb)],
        signer_cert=tsl_signer_no_ku,
        signer_key=tsl_signer_no_ku_key,
        issue_dt=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )
    with pytest.raises(TrustSignatureError):
        verify_tsl_xml_signature(tsl_bad_signer, synthetic_pki["ants_root_cert"])

    # 4) Signataire TSL avec AKI != SKI -> TrustSignatureError
    tsl_signer_bad_aki_key = _make_rsa_key()
    tsl_signer_bad_aki = _build_leaf_cert(
        "TSL2",
        tsl_signer_bad_aki_key,
        synthetic_pki["ants_root_cert"],
        synthetic_pki["ants_root_key"],
        not_before=nb,
        not_after=na,
        aki_override=b"\xff" * 20,
    )
    tsl_bad_aki = _build_signed_tsl_xml(
        ca_entries=[("FR06", synthetic_pki["ca_cert"], nb)],
        signer_cert=tsl_signer_bad_aki,
        signer_key=tsl_signer_bad_aki_key,
        issue_dt=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )
    with pytest.raises(TrustSignatureError):
        verify_tsl_xml_signature(tsl_bad_aki, synthetic_pki["ants_root_cert"])

    # 5) Signataire TSL hors fenêtre de validité à la date de signature -> TrustSignatureError
    tsl_expired_signer = _build_signed_tsl_xml(
        ca_entries=[("FR06", synthetic_pki["ca_cert"], nb)],
        signer_cert=synthetic_pki["tsl_signer_cert"],
        signer_key=synthetic_pki["tsl_signer_key"],
        issue_dt=dt.datetime(2040, 1, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2041, 1, 1, tzinfo=dt.timezone.utc),
        signing_dt=dt.datetime(2040, 1, 1, tzinfo=dt.timezone.utc),
    )
    with pytest.raises(TrustSignatureError):
        verify_tsl_xml_signature(tsl_expired_signer, synthetic_pki["ants_root_cert"])


def test_ssrf_redirects_private_ips_and_link_cap_sec04(monkeypatch):
    """SEC-04 : rejet IP privées/loopback/link-local, blocage redirections non sûres et limite de liens."""
    # 1) URLs initiales privées / loopback / link-local / localhost rejetées
    for unsafe_url in [
        "http://127.0.0.1/cert.der",
        "https://10.0.0.1/cert.der",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/cert.der",
        "https://localhost/cert.der",
    ]:
        assert _is_safe_http_url(unsafe_url) is None
        assert _fetch_bytes(unsafe_url) is None

    # Les noms de domaine publics/mockés restent acceptés
    assert _is_safe_http_url("https://good.example/cert.der") is not None
    assert _is_safe_http_url("https://sp.ants.gouv.fr/cev/cert.der") is not None

    # 2) Redirections bloquées par _SafeRedirectHandler
    handler = _SafeRedirectHandler()
    req = urllib.request.Request("https://good.example/start.der")
    fp = io.BytesIO(b"")
    headers = HTTPMessage()

    for blocked_target in [
        "file:///etc/passwd",
        "http://127.0.0.1/internal.der",
        "https://169.254.169.254/meta.der",
        "http://good.example/downgrade.der",  # HTTPS -> HTTP downgrade
    ]:
        with pytest.raises(urllib.error.URLError):
            handler.redirect_request(req, fp, 302, "Found", headers, blocked_target)

    # Redirection HTTPS -> HTTPS vers domaine public autorisée
    redirected = handler.redirect_request(
        req, fp, 302, "Found", headers, "https://cdn.example/next.der"
    )
    assert redirected is not None
    assert redirected.full_url == "https://cdn.example/next.der"

    # 3) Cap sur _extract_links (_MAX_LINKS_PER_PAGE = 500)
    many_links = b"".join(
        f'<a href="https://good.example/c{i}.der">c{i}</a>'.encode("ascii")
        for i in range(_MAX_LINKS_PER_PAGE + 50)
    )
    extracted = _extract_links(many_links, "https://good.example/dir/")
    assert len(extracted) == _MAX_LINKS_PER_PAGE


def test_inclusive_c14n_and_naive_iso_datetimes_supported(synthetic_pki):
    """QUAL-04 / QUAL-06 : support de C14N Inclusif (REC-xml-c14n-20010315) et normalisation UTC des dates ISO naïves."""
    c14n_inc = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    ca_cert = synthetic_pki["ca_cert"]
    signer_cert = synthetic_pki["tsl_signer_cert"]
    signer_key = synthetic_pki["tsl_signer_key"]

    cert_b64 = base64.b64encode(ca_cert.public_bytes(Encoding.DER)).decode("ascii")
    # Dates volontairement naïves (sans 'Z') pour tester QUAL-04
    unsigned_xml = (
        '<tsl:TrustServiceStatusList xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        'xmlns:tsl="http://uri.etsi.org/02231/v2#" '
        'xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">'
        "<tsl:SchemeInformation>"
        "<tsl:TSLSequenceNumber>77</tsl:TSLSequenceNumber>"
        "<tsl:ListIssueDateTime>2026-05-01T00:00:00</tsl:ListIssueDateTime>"
        "<tsl:NextUpdate><tsl:dateTime>2027-05-01T00:00:00</tsl:dateTime></tsl:NextUpdate>"
        "</tsl:SchemeInformation>"
        "<tsl:TrustServiceProviderList>"
        "<tsl:TrustServiceProvider>"
        "<tsl:TSPInformation>"
        '<tsl:TSPName><tsl:Name xml:lang="fr">Test CA FR06</tsl:Name></tsl:TSPName>'
        '<tsl:TSPTradeName><tsl:Name xml:lang="fr">FR06</tsl:Name></tsl:TSPTradeName>'
        "</tsl:TSPInformation>"
        "<tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation>"
        "<tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/PKC</tsl:ServiceTypeIdentifier>"
        f"<tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>{cert_b64}</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity>"
        "<tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/Svcstatus/inaccord</tsl:ServiceStatus>"
        "<tsl:StatusStartingTime>2020-01-01T00:00:00</tsl:StatusStartingTime>"
        "</tsl:ServiceInformation></tsl:TSPService></tsl:TSPServices>"
        "</tsl:TrustServiceProvider>"
        "</tsl:TrustServiceProviderList>"
        "</tsl:TrustServiceStatusList>"
    )
    c14n_doc = _independent_c14n(unsigned_xml, exclusive=False)
    doc_digest = base64.b64encode(hashlib.sha256(c14n_doc).digest()).decode("ascii")

    # Inclusive C14N hérite de tous les xmlns ancêtres (ds, tsl, xades)
    signed_props_inc = (
        '<xades:SignedProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        'xmlns:tsl="http://uri.etsi.org/02231/v2#" '
        'xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xades-inc-1">'
        "<xades:SignedSignatureProperties>"
        "<xades:SigningTime>2026-05-01T00:00:00</xades:SigningTime>"
        "</xades:SignedSignatureProperties>"
        "</xades:SignedProperties>"
    )
    c14n_sp = _independent_c14n(signed_props_inc, exclusive=False)
    sp_digest = base64.b64encode(hashlib.sha256(c14n_sp).digest()).decode("ascii")

    signed_info_for_digest = (
        '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        'xmlns:tsl="http://uri.etsi.org/02231/v2#" '
        'xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">'
        f'<ds:CanonicalizationMethod Algorithm="{c14n_inc}"/>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        '<ds:Reference URI="">'
        "<ds:Transforms>"
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        f'<ds:Transform Algorithm="{c14n_inc}"/>'
        "</ds:Transforms>"
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f"<ds:DigestValue>{doc_digest}</ds:DigestValue>"
        "</ds:Reference>"
        '<ds:Reference URI="#xades-inc-1">'
        "<ds:Transforms>"
        f'<ds:Transform Algorithm="{c14n_inc}"/>'
        "</ds:Transforms>"
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f"<ds:DigestValue>{sp_digest}</ds:DigestValue>"
        "</ds:Reference>"
        "</ds:SignedInfo>"
    )
    c14n_si = _independent_c14n(signed_info_for_digest, exclusive=False)
    sig_bytes = signer_key.sign(c14n_si, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    signer_b64 = base64.b64encode(signer_cert.public_bytes(Encoding.DER)).decode(
        "ascii"
    )

    signed_info_inner = signed_info_for_digest.replace(
        ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:tsl="http://uri.etsi.org/02231/v2#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"',
        "",
        1,
    )
    signed_props_inner = signed_props_inc.replace(
        ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:tsl="http://uri.etsi.org/02231/v2#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"',
        "",
        1,
    )
    sig_block = (
        '<ds:Signature Id="sig-inc-1">'
        + signed_info_inner
        + f"<ds:SignatureValue>{sig_b64}</ds:SignatureValue>"
        + f"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{signer_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
        + '<ds:Object><xades:QualifyingProperties Target="#sig-inc-1">'
        + signed_props_inner
        + "</xades:QualifyingProperties></ds:Object>"
        + "</ds:Signature>"
    )
    tsl_inc = unsigned_xml.replace(
        "</tsl:TrustServiceStatusList>", sig_block + "</tsl:TrustServiceStatusList>"
    ).encode("utf-8")

    meta = verify_tsl_xml_signature(tsl_inc, synthetic_pki["ants_root_cert"])
    assert meta.sequence_number == 77
    assert meta.issue_date == dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc)
    assert meta.next_update == dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc)

    # from_tsl avec dates naïves (StatusStartingTime sans Z) ne doit pas lever TypeError lors du tri
    resolver = KeyResolver.from_tsl(
        tsl_inc, root_ca_cert=synthetic_pki["ants_root_cert"]
    )
    assert resolver.tsl_sequence_number == 77


def test_expired_and_future_crls_make_verification_unavailable(synthetic_pki):
    doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )
    for last_update, next_update in [
        (
            dt.datetime(2022, 1, 1, tzinfo=dt.timezone.utc),
            dt.datetime(2022, 1, 2, tzinfo=dt.timezone.utc),
        ),
        (
            dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc),
            dt.datetime(2027, 1, 2, tzinfo=dt.timezone.utc),
        ),
    ]:
        crl = _build_crl(
            synthetic_pki["ca_cert"],
            synthetic_pki["ca_key"],
            last_update=last_update,
            next_update=next_update,
        )
        resolver = KeyResolver.from_tsl(
            synthetic_pki["tsl_bytes"],
            root_ca_cert=synthetic_pki["ants_root_cert"],
            leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
            crls_by_ca={"FR06": [crl]},
        )
        decoded = decode_2d_doc(
            doc,
            key_resolver=resolver,
            evaluation_date=dt.date(2026, 11, 17),
        )
        assert decoded.is_valid is False
        assert decoded.verification is not None
        assert decoded.verification.status == VerificationStatus.RESOLVER_UNAVAILABLE


def test_packaged_expired_fr01_crl_is_not_accepted_as_current_evidence():
    reset_default_key_resolver()
    resolver = get_default_key_resolver()
    with pytest.raises(ResolverUnavailableError):
        resolver.resolve_for_verification(
            "FR01",
            "SFR0",
            reference_date=dt.date(2012, 6, 28),
            evaluation_date=dt.date(2026, 11, 17),
        )


def test_from_network_fails_closed_when_crl_download_fails(monkeypatch, synthetic_pki):
    tsl_with_uri = _build_signed_tsl_xml(
        ca_entries=[
            (
                "FR06",
                synthetic_pki["ca_cert"],
                dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
            )
        ],
        signer_cert=synthetic_pki["tsl_signer_cert"],
        signer_key=synthetic_pki["tsl_signer_key"],
        issue_dt=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
        tsp_uris={"FR06": "https://ca.example/fr06.der"},
    )
    leaf_der = synthetic_pki["leaf_cert"].public_bytes(Encoding.DER)

    def _fetch_without_crl(url: str, timeout: int = 15) -> bytes | None:
        if url == "https://tsl.example/tsl.xml":
            return tsl_with_uri
        if url == "https://ca.example/fr06.der":
            return leaf_der
        return None

    monkeypatch.setattr(key_resolver_mod, "_fetch_bytes", _fetch_without_crl)
    monkeypatch.setattr(
        key_resolver_mod,
        "extract_crl_urls_from_certs",
        lambda certs: ["https://ca.example/fr06.crl"],
    )
    with pytest.raises(ResolverUnavailableError):
        KeyResolver.from_network(
            "https://tsl.example/tsl.xml",
            root_ca_cert=synthetic_pki["ants_root_cert"],
            evaluation_date=dt.date(2026, 11, 17),
        )

    def _fetch_with_crl(url: str, timeout: int = 15) -> bytes | None:
        if url == "https://ca.example/fr06.crl":
            return synthetic_pki["crl"].public_bytes(Encoding.DER)
        return _fetch_without_crl(url, timeout)

    monkeypatch.setattr(key_resolver_mod, "_fetch_bytes", _fetch_with_crl)
    resolver = KeyResolver.from_network(
        "https://tsl.example/tsl.xml",
        root_ca_cert=synthetic_pki["ants_root_cert"],
        evaluation_date=dt.date(2026, 11, 17),
    )
    doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )
    decoded = decode_2d_doc(
        doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert decoded.is_valid is True
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.VERIFIED


def test_unknown_critical_crl_entry_extension_rejects_entire_crl(synthetic_pki):
    unsupported = x509.UnrecognizedExtension(
        x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00"
    )
    crl = _build_crl(
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
        revoked_entries=[
            (
                987654321,
                dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc),
                x509.ReasonFlags.key_compromise,
            )
        ],
        revoked_entry_extensions=[x509.Extension(unsupported.oid, True, unsupported)],
    )
    with pytest.raises(TrustSignatureError):
        validate_crl_against_ca(crl, synthetic_pki["ca_cert"])


def test_unavailable_actual_signer_is_not_reported_as_signature_invalid(synthetic_pki):
    tsl, _, _, new_leaf_cert, _, new_crl = _build_rotated_issuer_fixture(synthetic_pki)
    expired_old_crl = _build_crl(
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        last_update=dt.datetime(2022, 1, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2022, 1, 2, tzinfo=dt.timezone.utc),
    )
    resolver = KeyResolver.from_tsl(
        tsl,
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"], new_leaf_cert]},
        crls_by_ca={"FR06": [expired_old_crl, new_crl]},
    )
    doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )
    decoded = decode_2d_doc(
        doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert decoded.is_valid is False
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.RESOLVER_UNAVAILABLE


def test_whole_document_reference_covers_outer_processing_instructions(synthetic_pki):
    tampered = _build_fixture_tsl(synthetic_pki) + b"<?review tampered?>"
    with pytest.raises(TrustSignatureError):
        verify_tsl_xml_signature(tampered, synthetic_pki["ants_root_cert"])

    valid = _build_fixture_tsl(
        synthetic_pki,
        document_suffix="<?review valid?>",
    )
    metadata = verify_tsl_xml_signature(valid, synthetic_pki["ants_root_cert"])
    assert metadata.sequence_number == 99


def _build_rotated_issuer_fixture(synthetic_pki):
    new_ca_key = _make_ec_key()
    new_ca_cert = _build_ca_cert(
        "FR06",
        new_ca_key,
        not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2032, 1, 1, tzinfo=dt.timezone.utc),
    )
    new_leaf_key = _make_ec_key()
    new_leaf_cert = _build_leaf_cert(
        "FPE2",
        new_leaf_key,
        new_ca_cert,
        new_ca_key,
        not_before=dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc),
        serial=4242,
    )
    status_start = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    tsl = _build_signed_tsl_xml(
        ca_entries=[
            ("FR06", synthetic_pki["ca_cert"], status_start),
            ("FR06", new_ca_cert, status_start),
        ],
        signer_cert=synthetic_pki["tsl_signer_cert"],
        signer_key=synthetic_pki["tsl_signer_key"],
        issue_dt=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )
    old_crl = _build_crl(
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
        revoked_entries=[
            (
                4242,
                dt.datetime(2021, 6, 1, tzinfo=dt.timezone.utc),
                x509.ReasonFlags.cessation_of_operation,
            )
        ],
    )
    new_crl = _build_crl(
        new_ca_cert,
        new_ca_key,
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )
    return tsl, new_ca_cert, new_leaf_key, new_leaf_cert, old_crl, new_crl


def test_trust_store_requires_crl_for_actual_issuer(tmp_path: Path, synthetic_pki):
    tsl, new_ca_cert, _, new_leaf_cert, old_crl, new_crl = (
        _build_rotated_issuer_fixture(synthetic_pki)
    )
    (tmp_path / "ants_tsl_root_ca.pem").write_bytes(
        synthetic_pki["ants_root_cert"].public_bytes(Encoding.PEM)
    )
    (tmp_path / "tsl_signed.xml").write_bytes(tsl)
    (tmp_path / "trusted_leaves").mkdir()
    (tmp_path / "trusted_leaves" / "FR06.pem").write_bytes(
        new_leaf_cert.public_bytes(Encoding.PEM)
    )
    (tmp_path / "crls").mkdir()
    (tmp_path / "crls" / "FR06.crl").write_bytes(old_crl.public_bytes(Encoding.DER))

    with pytest.raises(ResolverUnavailableError):
        KeyResolver.from_trust_store(tmp_path)

    issuer_id = new_ca_cert.fingerprint(hashes.SHA256()).hex()
    (tmp_path / "crls" / f"FR06-{issuer_id}.crl").write_bytes(
        new_crl.public_bytes(Encoding.DER)
    )
    resolver = KeyResolver.from_trust_store(tmp_path)
    assert resolver.available_cert_ids("FR06") == {"FPE2"}


def test_crl_serial_collisions_are_issuer_scoped(synthetic_pki):
    tsl, _, new_leaf_key, new_leaf_cert, old_crl, new_crl = (
        _build_rotated_issuer_fixture(synthetic_pki)
    )
    resolver = KeyResolver.from_tsl(
        tsl,
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [new_leaf_cert]},
        crls_by_ca={"FR06": [old_crl, new_crl]},
    )
    doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=new_leaf_key,
    )
    decoded = decode_2d_doc(
        doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert decoded.is_valid is True
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.VERIFIED


def test_default_tsl_freshness_uses_current_instant(monkeypatch, synthetic_pki):
    tsl = _build_signed_tsl_xml(
        ca_entries=[
            (
                "FR06",
                synthetic_pki["ca_cert"],
                dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
            )
        ],
        signer_cert=synthetic_pki["tsl_signer_cert"],
        signer_key=synthetic_pki["tsl_signer_key"],
        issue_dt=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 5, 1, 0, 0, tzinfo=dt.timezone.utc),
    )
    crl = _build_crl(
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2027, 5, 2, tzinfo=dt.timezone.utc),
    )
    resolver = KeyResolver.from_tsl(
        tsl,
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
        crls_by_ca={"FR06": [crl]},
    )
    doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )

    class _FrozenDateTime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            value = cls(2027, 5, 1, 12, 0, tzinfo=dt.timezone.utc)
            return value if tz is not None else value.replace(tzinfo=None)

    monkeypatch.setattr(key_resolver_mod.dt, "datetime", _FrozenDateTime)
    monkeypatch.setattr("fr_2ddoc_parser.model.models.datetime", _FrozenDateTime)
    decoded = decode_2d_doc(doc, key_resolver=resolver)
    assert decoded.is_valid is False
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.TRUST_LIST_EXPIRED
    assert decoded.verification.tsl_freshness == TrustListFreshness.STALE


def test_inclusive_c14n_matches_independent_libxml2_vector():
    document = minidom.parseString(
        '<a:root xmlns:a="urn:a" xmlns:unused="urn:unused"><a:x/></a:root>'
    )
    root = document.documentElement
    assert root is not None
    assert _canonicalize_subtree(root, exclusive=False) == (
        b'<a:root xmlns:a="urn:a" xmlns:unused="urn:unused"><a:x></a:x></a:root>'
    )
    assert _canonicalize_subtree(root, exclusive=True) == (
        b'<a:root xmlns:a="urn:a"><a:x></a:x></a:root>'
    )


def test_unsupported_xpath_filter_is_rejected(synthetic_pki):
    transform = (
        b"<ds:Transforms><ds:Transform "
        b'Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
        b'<dsig-filter2:XPath xmlns:dsig-filter2="http://www.w3.org/2002/06/xmldsig-filter2" '
        b'Filter="subtract">/descendant::ds:KeyInfo</dsig-filter2:XPath>'
        b"</ds:Transform></ds:Transforms>"
    )
    original_transforms = (
        b'<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>'
    )
    tsl = synthetic_pki["tsl_bytes"].replace(
        original_transforms,
        transform,
        1,
    )
    with pytest.raises(TrustSignatureError, match="xmldsig-filter2"):
        verify_tsl_xml_signature(tsl, synthetic_pki["ants_root_cert"])


def _build_fixture_tsl(synthetic_pki, **kwargs) -> bytes:
    return _build_signed_tsl_xml(
        ca_entries=[
            (
                "FR06",
                synthetic_pki["ca_cert"],
                dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
            )
        ],
        signer_cert=synthetic_pki["tsl_signer_cert"],
        signer_key=synthetic_pki["tsl_signer_key"],
        issue_dt=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
        **kwargs,
    )


def test_delta_restricted_and_unknown_critical_crls_are_rejected(synthetic_pki):
    idp = x509.IssuingDistributionPoint(
        full_name=None,
        relative_name=None,
        only_contains_user_certs=False,
        only_contains_ca_certs=True,
        only_some_reasons=None,
        indirect_crl=False,
        only_contains_attribute_certs=False,
    )
    unsupported_values = [
        x509.DeltaCRLIndicator(123),
        idp,
        x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00"),
    ]
    for value in unsupported_values:
        crl = _build_crl(
            synthetic_pki["ca_cert"],
            synthetic_pki["ca_key"],
            last_update=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
            next_update=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
            extra_extensions=[x509.Extension(value.oid, True, value)],
        )
        with pytest.raises(TrustSignatureError):
            validate_crl_against_ca(crl, synthetic_pki["ca_cert"])


def test_unavailable_rotated_candidate_does_not_block_valid_candidate(synthetic_pki):
    tsl, _, new_leaf_key, new_leaf_cert, _, new_crl = _build_rotated_issuer_fixture(
        synthetic_pki
    )
    expired_old_crl = _build_crl(
        synthetic_pki["ca_cert"],
        synthetic_pki["ca_key"],
        last_update=dt.datetime(2022, 1, 1, tzinfo=dt.timezone.utc),
        next_update=dt.datetime(2022, 1, 2, tzinfo=dt.timezone.utc),
    )
    resolver = KeyResolver.from_tsl(
        tsl,
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"], new_leaf_cert]},
        crls_by_ca={"FR06": [expired_old_crl, new_crl]},
    )
    doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=new_leaf_key,
    )
    decoded = decode_2d_doc(
        doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert decoded.is_valid is True
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.VERIFIED


def test_same_key_ca_renewal_preserves_historical_verification(synthetic_pki):
    renewed_ca_cert = _build_ca_cert(
        "FR06",
        synthetic_pki["ca_key"],
        not_before=dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2035, 1, 1, tzinfo=dt.timezone.utc),
    )
    tsl = _build_signed_tsl_xml(
        ca_entries=[
            (
                "FR06",
                synthetic_pki["ca_cert"],
                dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
            ),
            (
                "FR06",
                renewed_ca_cert,
                dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc),
            ),
        ],
        signer_cert=synthetic_pki["tsl_signer_cert"],
        signer_key=synthetic_pki["tsl_signer_key"],
        issue_dt=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        next_update_dt=dt.datetime(2027, 5, 1, tzinfo=dt.timezone.utc),
    )
    resolver = KeyResolver.from_tsl(
        tsl,
        root_ca_cert=synthetic_pki["ants_root_cert"],
        leaf_certs_by_ca={"FR06": [synthetic_pki["leaf_cert"]]},
        crls_by_ca={"FR06": [synthetic_pki["crl"]]},
    )
    doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=dt.date(2022, 6, 15),
        signature_date=dt.date(2022, 6, 15),
        private_key=synthetic_pki["leaf_key"],
    )
    decoded = decode_2d_doc(
        doc,
        key_resolver=resolver,
        evaluation_date=dt.date(2026, 11, 17),
    )
    assert decoded.is_valid is True
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.VERIFIED


def test_implicit_reference_canonicalization_is_inclusive(synthetic_pki):
    tsl = _build_fixture_tsl(
        synthetic_pki,
        reference_c14n=None,
        signed_properties_c14n=None,
    )
    metadata = verify_tsl_xml_signature(tsl, synthetic_pki["ants_root_cert"])
    assert metadata.sequence_number == 99


def test_inclusive_c14n_inherits_nearest_xml_namespace_attributes():
    document = minidom.parseString(
        '<r xml:lang="fr" xml:space="preserve" xml:base="https://example.test/root/" xml:id="root-id"><x xml:lang="en"/></r>'
    )
    root = document.documentElement
    assert root is not None
    child = root.firstChild
    assert isinstance(child, minidom.Element)
    assert _canonicalize_subtree(child, exclusive=False) == (
        b'<x xml:base="https://example.test/root/" xml:id="root-id" '
        b'xml:lang="en" xml:space="preserve"></x>'
    )


def test_inclusive_signature_inherits_root_xml_attributes(synthetic_pki):
    tsl = _build_fixture_tsl(
        synthetic_pki,
        reference_c14n="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        signed_properties_c14n="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        signed_info_c14n="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        root_attributes=' xml:lang="fr"',
    )
    metadata = verify_tsl_xml_signature(tsl, synthetic_pki["ants_root_cert"])
    assert metadata.sequence_number == 99


def test_exclusive_c14n_prefix_list_is_explicitly_rejected(synthetic_pki):
    tsl = _build_fixture_tsl(synthetic_pki)
    prefix_list = (
        '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">'
        '<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" '
        'PrefixList="tsl"/></ds:Transform>'
    )
    tsl = tsl.replace(
        b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>',
        prefix_list.encode("ascii"),
        1,
    )
    with pytest.raises(TrustSignatureError, match="InclusiveNamespaces"):
        verify_tsl_xml_signature(tsl, synthetic_pki["ants_root_cert"])


def test_filter2_requires_correct_ds_namespace_binding():
    tsl = Path("src/fr_2ddoc_parser/crypto/keys/tsl_signed.xml").read_bytes()
    tsl = tsl.replace(
        b'Filter="subtract">/descendant::ds:Signature',
        b'Filter="subtract" xmlns:ds="urn:wrong">/descendant::ds:Signature',
        1,
    )
    with pytest.raises(TrustSignatureError, match="xmldsig-filter2"):
        KeyResolver.from_tsl(tsl)


def test_multiple_c14n_transforms_are_rejected(synthetic_pki):
    tsl = _build_fixture_tsl(synthetic_pki)
    tsl = tsl.replace(
        b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>',
        b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        b'<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>',
        1,
    )
    with pytest.raises(TrustSignatureError, match="C14N"):
        verify_tsl_xml_signature(tsl, synthetic_pki["ants_root_cert"])


def test_from_network_rejects_when_no_leaf_can_be_downloaded(
    monkeypatch, synthetic_pki
):
    tsl = _build_fixture_tsl(
        synthetic_pki,
        tsp_uris={"FR06": "https://ca.example/fr06.der"},
    )
    monkeypatch.setattr(
        key_resolver_mod,
        "_fetch_bytes",
        lambda url, timeout=15: (
            tsl if url == "https://tsl.example/tsl.xml" else b"not a certificate"
        ),
    )
    with pytest.raises(ResolverUnavailableError):
        KeyResolver.from_network(
            "https://tsl.example/tsl.xml",
            root_ca_cert=synthetic_pki["ants_root_cert"],
            evaluation_date=dt.date(2026, 11, 17),
        )
