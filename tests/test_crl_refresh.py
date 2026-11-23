from __future__ import annotations

import base64
import datetime as dt
import threading
from concurrent.futures import ThreadPoolExecutor

import pydantic
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from fr_2ddoc_parser.api import (
    CrlRefreshResult,
    decode_2d_doc,
    refresh_default_crls,
)
from fr_2ddoc_parser.crypto import key_resolver as key_resolver_mod
from fr_2ddoc_parser.crypto.key_resolver import (
    KeyResolver,
    _CertRecord,
    get_default_key_resolver,
    reset_default_key_resolver,
)
from fr_2ddoc_parser.crypto.trust_validator import TslMetadata
from fr_2ddoc_parser.model.models import VerificationStatus


def _date_to_hex_days(d: dt.date) -> str:
    days = (d - dt.date(2000, 1, 1)).days
    return f"{days:04X}"


def _build_signed_2ddoc(
    *,
    ca_id: str,
    cert_id: str,
    issue_date: dt.date,
    signature_date: dt.date,
    private_key: ec.EllipticCurvePrivateKey,
) -> str:
    issue_hex = _date_to_hex_days(issue_date)
    sig_hex = _date_to_hex_days(signature_date)
    header = f"DC04{ca_id}{cert_id}{issue_hex}{sig_hex}0001FR"
    payload_body = (
        "26FR247500010JEAN/DUPONT\x1d20\x1d21\x1d221 RUE TEST\x1d23\x1d25PARIS\x1d"
    )
    sign_payload = (header + payload_body).encode("utf-8")
    der_sig = private_key.sign(sign_payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    coord_size = (private_key.curve.key_size + 7) // 8
    raw_sig = r.to_bytes(coord_size, "big") + s.to_bytes(coord_size, "big")
    sig_b32 = base64.b32encode(raw_sig).decode("ascii").rstrip("=")
    return f"{header}{payload_body}\x1f{sig_b32}"


def _make_name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEST ANTS"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _build_ca(
    cn: str,
    *,
    not_before: dt.datetime,
    not_after: dt.datetime,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = _make_name(cn)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
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
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, cert


def _build_leaf(
    cert_id: str,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    *,
    not_before: dt.datetime,
    not_after: dt.datetime,
    crl_urls: list[str] | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    issuer_ski = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value
    builder = (
        x509.CertificateBuilder()
        .subject_name(_make_name(cert_id))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
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
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
            critical=False,
        )
    )
    if crl_urls:
        dps = [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(url)],
                relative_name=None,
                crl_issuer=None,
                reasons=None,
            )
            for url in crl_urls
        ]
        builder = builder.add_extension(
            x509.CRLDistributionPoints(dps),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return leaf_key, cert


def _build_crl(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    *,
    last_update: dt.datetime,
    next_update: dt.datetime,
    revoked_serials: list[tuple[int, dt.datetime]] | None = None,
) -> x509.CertificateRevocationList:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(last_update)
        .next_update(next_update)
    )
    for serial, rev_dt in revoked_serials or []:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(rev_dt)
            .build()
        )
    return builder.sign(ca_key, hashes.SHA256())


def _make_resolver(
    *,
    ca_specs: dict[
        str,
        tuple[
            x509.Certificate, x509.Certificate, x509.CertificateRevocationList | None
        ],
    ],
    tsl_next_update: dt.datetime,
) -> KeyResolver:
    ca_records: dict[str, list[_CertRecord]] = {}
    leaf_candidates: dict[tuple[str, str], list[x509.Certificate]] = {}
    crls_by_ca: dict[str, list[x509.CertificateRevocationList]] = {}
    for ca_id, (ca_cert, leaf_cert, crl) in ca_specs.items():
        ca_records[ca_id] = [
            _CertRecord(
                ca_id=ca_id,
                pem_der=ca_cert.public_bytes(Encoding.DER),
                cert=ca_cert,
                status_start=ca_cert.not_valid_before_utc,
            )
        ]
        cn = str(
            leaf_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        ).upper()
        leaf_candidates[(ca_id, cn)] = [leaf_cert]
        if crl is not None:
            crls_by_ca[ca_id] = [crl]

    return KeyResolver(
        ca_records=ca_records,
        leaf_candidates=leaf_candidates,
        crls_by_ca=crls_by_ca,
        tsl_metadata=TslMetadata(
            sequence_number=99,
            issue_date=tsl_next_update - dt.timedelta(days=365),
            next_update=tsl_next_update,
            signer_cn="ANTS CACHET 2DDOC",
        ),
        require_crls=True,
    )


def test_refresh_expired_crl_restores_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = dt.datetime.now(dt.UTC)
    ca_key, ca_cert = _build_ca(
        "CA FR06",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    crl_url = "https://crl.example.gouv.fr/fr06.crl"
    leaf_key, leaf_cert = _build_leaf(
        "FPE2",
        ca_cert,
        ca_key,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=[crl_url],
    )
    expired_crl = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(days=10),
        next_update=now - dt.timedelta(days=3),
    )
    fresh_crl = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(hours=1),
        next_update=now + dt.timedelta(days=5),
    )

    resolver = _make_resolver(
        ca_specs={"FR06": (ca_cert, leaf_cert, expired_crl)},
        tsl_next_update=now + dt.timedelta(days=180),
    )
    raw_doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=now.date(),
        signature_date=now.date(),
        private_key=leaf_key,
    )

    # Avant rafraîchissement : fail-closed RESOLVER_UNAVAILABLE
    before = decode_2d_doc(raw_doc, key_resolver=resolver)
    assert before.is_valid is False
    assert before.verification is not None
    assert before.verification.status == VerificationStatus.RESOLVER_UNAVAILABLE
    assert resolver.has_expired_crls() is True
    assert resolver.get_expired_crl_cas() == ("FR06",)

    fetched_urls: list[str] = []

    def fake_fetch(url: str, timeout: int = 10) -> bytes | None:
        fetched_urls.append(url)
        assert url == crl_url
        assert timeout == 7
        return fresh_crl.public_bytes(Encoding.DER)

    monkeypatch.setattr(key_resolver_mod, "_fetch_bytes", fake_fetch)

    result = resolver.refresh_crls(timeout=7)
    assert result == CrlRefreshResult(
        refreshed_cas=("FR06",),
        skipped_fresh_cas=(),
        failed_cas={},
        expired_cas=(),
    )
    assert fetched_urls == [crl_url]
    assert resolver.has_expired_crls() is False
    assert resolver.get_expired_crl_cas() == ()

    # Après rafraîchissement : VERIFIED
    after = decode_2d_doc(raw_doc, key_resolver=resolver)
    assert after.is_valid is True
    assert after.verification is not None
    assert after.verification.status == VerificationStatus.VERIFIED


def test_only_expired_skips_fresh_ca_beyond_margin_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = dt.datetime.now(dt.UTC)
    ca_key_fresh, ca_cert_fresh = _build_ca(
        "CA FR06",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    _, leaf_fresh = _build_leaf(
        "FPE2",
        ca_cert_fresh,
        ca_key_fresh,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=["https://crl.example.gouv.fr/fr06.crl"],
    )
    fresh_crl = _build_crl(
        ca_cert_fresh,
        ca_key_fresh,
        last_update=now - dt.timedelta(hours=1),
        next_update=now + dt.timedelta(days=5),
    )

    ca_key_soon, ca_cert_soon = _build_ca(
        "CA FR07",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    _, leaf_soon = _build_leaf(
        "AAA1",
        ca_cert_soon,
        ca_key_soon,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=["https://crl.example.gouv.fr/fr07.crl"],
    )
    # Expire dans 6h -> encore applicable maintenant, mais dans la marge de 24h
    expiring_soon_crl = _build_crl(
        ca_cert_soon,
        ca_key_soon,
        last_update=now - dt.timedelta(days=2),
        next_update=now + dt.timedelta(hours=6),
    )
    renewed_fr07_crl = _build_crl(
        ca_cert_soon,
        ca_key_soon,
        last_update=now - dt.timedelta(minutes=5),
        next_update=now + dt.timedelta(days=6),
    )

    resolver = _make_resolver(
        ca_specs={
            "FR06": (ca_cert_fresh, leaf_fresh, fresh_crl),
            "FR07": (ca_cert_soon, leaf_soon, expiring_soon_crl),
        },
        tsl_next_update=now + dt.timedelta(days=180),
    )

    # Marge 0 : aucune expirée ; marge 24h : FR07 est proche de l'expiration
    assert resolver.get_expired_crl_cas() == ()
    assert resolver.get_expired_crl_cas(refresh_margin=dt.timedelta(hours=24)) == (
        "FR07",
    )

    fetched: list[str] = []

    def fake_fetch(url: str, timeout: int = 10) -> bytes | None:
        fetched.append(url)
        if url.endswith("fr07.crl"):
            return renewed_fr07_crl.public_bytes(Encoding.DER)
        raise AssertionError(f"URL inattendue appelée: {url}")

    monkeypatch.setattr(key_resolver_mod, "_fetch_bytes", fake_fetch)

    res = resolver.refresh_crls(
        only_expired=True,
        refresh_margin=dt.timedelta(hours=24),
    )
    assert fetched == ["https://crl.example.gouv.fr/fr07.crl"]
    assert res == CrlRefreshResult(
        refreshed_cas=("FR07",),
        skipped_fresh_cas=("FR06",),
        failed_cas={},
        expired_cas=(),
    )


def test_only_expired_false_forces_refresh_of_fresh_ca(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = dt.datetime.now(dt.UTC)
    ca_key, ca_cert = _build_ca(
        "CA FR06",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    crl_url = "https://crl.example.gouv.fr/fr06.crl"
    _, leaf_cert = _build_leaf(
        "FPE2",
        ca_cert,
        ca_key,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=[crl_url],
    )
    existing_fresh = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(hours=1),
        next_update=now + dt.timedelta(days=5),
    )
    newer_fresh = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(minutes=5),
        next_update=now + dt.timedelta(days=7),
    )
    resolver = _make_resolver(
        ca_specs={"FR06": (ca_cert, leaf_cert, existing_fresh)},
        tsl_next_update=now + dt.timedelta(days=180),
    )

    fetched: list[str] = []

    def fake_fetch(url: str, timeout: int = 10) -> bytes | None:
        fetched.append(url)
        return newer_fresh.public_bytes(Encoding.DER)

    monkeypatch.setattr(key_resolver_mod, "_fetch_bytes", fake_fetch)

    res = resolver.refresh_crls(only_expired=False)
    assert fetched == [crl_url]
    assert res.refreshed_cas == ("FR06",)
    assert res.skipped_fresh_cas == ()
    assert res.failed_cas == {}
    assert res.expired_cas == ()


@pytest.mark.parametrize(
    ("bad_mode", "expected_reason"),
    [
        ("wrong_key", "invalid_crl_signature"),
        ("corrupt_bytes", "invalid_crl_format"),
        ("expired_crl", "crl_not_applicable"),
        ("network_none", "fetch_failed"),
    ],
)
def test_fail_closed_rejects_bad_crl_and_preserves_existing_state(
    monkeypatch: pytest.MonkeyPatch,
    bad_mode: str,
    expected_reason: str,
) -> None:
    now = dt.datetime.now(dt.UTC)
    ca_key, ca_cert = _build_ca(
        "CA FR06",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    rogue_key, _ = _build_ca(
        "CA ROGUE",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    crl_url = "https://crl.example.gouv.fr/fr06.crl"
    leaf_key, leaf_cert = _build_leaf(
        "FPE2",
        ca_cert,
        ca_key,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=[crl_url],
    )
    raw_doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=now.date(),
        signature_date=now.date(),
        private_key=leaf_key,
    )

    if bad_mode == "wrong_key":
        # Même subject mais signée par une autre clé privée
        bad_payload: bytes | None = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now - dt.timedelta(hours=1))
            .next_update(now + dt.timedelta(days=5))
            .sign(rogue_key, hashes.SHA256())
            .public_bytes(Encoding.DER)
        )
    elif bad_mode == "corrupt_bytes":
        bad_payload = b"not-a-valid-crl-payload"
    elif bad_mode == "expired_crl":
        bad_payload = _build_crl(
            ca_cert,
            ca_key,
            last_update=now - dt.timedelta(days=10),
            next_update=now - dt.timedelta(days=1),
        ).public_bytes(Encoding.DER)
    else:
        bad_payload = None

    monkeypatch.setattr(
        key_resolver_mod, "_fetch_bytes", lambda url, timeout=10: bad_payload
    )

    # Cas 1 : CRL existante expirée -> reste RESOLVER_UNAVAILABLE
    expired_crl = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(days=10),
        next_update=now - dt.timedelta(days=2),
    )
    resolver_expired = _make_resolver(
        ca_specs={"FR06": (ca_cert, leaf_cert, expired_crl)},
        tsl_next_update=now + dt.timedelta(days=180),
    )
    res_expired = resolver_expired.refresh_crls()
    assert res_expired.refreshed_cas == ()
    assert res_expired.failed_cas == {"FR06": expected_reason}
    assert res_expired.expired_cas == ("FR06",)
    decoded_exp = decode_2d_doc(raw_doc, key_resolver=resolver_expired)
    assert decoded_exp.is_valid is False
    assert decoded_exp.verification is not None
    assert decoded_exp.verification.status == VerificationStatus.RESOLVER_UNAVAILABLE

    # Cas 2 : CRL existante fraîche + only_expired=False -> CRL fraîche préservée !
    fresh_crl = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(hours=1),
        next_update=now + dt.timedelta(days=5),
    )
    resolver_fresh = _make_resolver(
        ca_specs={"FR06": (ca_cert, leaf_cert, fresh_crl)},
        tsl_next_update=now + dt.timedelta(days=180),
    )
    res_fresh = resolver_fresh.refresh_crls(only_expired=False)
    assert res_fresh.refreshed_cas == ()
    assert res_fresh.failed_cas == {"FR06": expected_reason}
    assert res_fresh.expired_cas == ()
    decoded_fresh = decode_2d_doc(raw_doc, key_resolver=resolver_fresh)
    assert decoded_fresh.is_valid is True
    assert decoded_fresh.verification is not None
    assert decoded_fresh.verification.status == VerificationStatus.VERIFIED


def test_ca_isolation_failure_on_fr01_does_not_block_fr06(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = dt.datetime.now(dt.UTC)
    fr01_key, fr01_cert = _build_ca(
        "CA FR01",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    _, fr01_leaf = _build_leaf(
        "A001",
        fr01_cert,
        fr01_key,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=["https://crl.example.gouv.fr/fr01.crl"],
    )
    fr01_expired = _build_crl(
        fr01_cert,
        fr01_key,
        last_update=now - dt.timedelta(days=1000),
        next_update=now - dt.timedelta(days=990),
    )

    fr06_key, fr06_cert = _build_ca(
        "CA FR06",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    fr06_leaf_key, fr06_leaf = _build_leaf(
        "FPE2",
        fr06_cert,
        fr06_key,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=["https://crl.example.gouv.fr/fr06.crl"],
    )
    fr06_expired = _build_crl(
        fr06_cert,
        fr06_key,
        last_update=now - dt.timedelta(days=10),
        next_update=now - dt.timedelta(days=2),
    )
    fr06_fresh = _build_crl(
        fr06_cert,
        fr06_key,
        last_update=now - dt.timedelta(hours=1),
        next_update=now + dt.timedelta(days=4),
    )

    resolver = _make_resolver(
        ca_specs={
            "FR01": (fr01_cert, fr01_leaf, fr01_expired),
            "FR06": (fr06_cert, fr06_leaf, fr06_expired),
        },
        tsl_next_update=now + dt.timedelta(days=180),
    )

    def fake_fetch(url: str, timeout: int = 10) -> bytes | None:
        if "fr01" in url:
            return None  # Panne réseau / serveur legacy indisponible
        if "fr06" in url:
            return fr06_fresh.public_bytes(Encoding.DER)
        return None

    monkeypatch.setattr(key_resolver_mod, "_fetch_bytes", fake_fetch)

    res = resolver.refresh_crls()
    assert res == CrlRefreshResult(
        refreshed_cas=("FR06",),
        skipped_fresh_cas=(),
        failed_cas={"FR01": "fetch_failed"},
        expired_cas=("FR01",),
    )

    raw_doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=now.date(),
        signature_date=now.date(),
        private_key=fr06_leaf_key,
    )
    decoded = decode_2d_doc(raw_doc, key_resolver=resolver)
    assert decoded.is_valid is True
    assert decoded.verification is not None
    assert decoded.verification.status == VerificationStatus.VERIFIED


def test_filter_by_ca_ids_only_fetches_targeted_ca(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = dt.datetime.now(dt.UTC)
    fr01_key, fr01_cert = _build_ca(
        "CA FR01",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    _, fr01_leaf = _build_leaf(
        "A001",
        fr01_cert,
        fr01_key,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=["https://crl.example.gouv.fr/fr01.crl"],
    )
    fr01_expired = _build_crl(
        fr01_cert,
        fr01_key,
        last_update=now - dt.timedelta(days=20),
        next_update=now - dt.timedelta(days=10),
    )

    fr06_key, fr06_cert = _build_ca(
        "CA FR06",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    _, fr06_leaf = _build_leaf(
        "FPE2",
        fr06_cert,
        fr06_key,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=["https://crl.example.gouv.fr/fr06.crl"],
    )
    fr06_expired = _build_crl(
        fr06_cert,
        fr06_key,
        last_update=now - dt.timedelta(days=10),
        next_update=now - dt.timedelta(days=2),
    )
    fr06_fresh = _build_crl(
        fr06_cert,
        fr06_key,
        last_update=now - dt.timedelta(hours=1),
        next_update=now + dt.timedelta(days=4),
    )

    resolver = _make_resolver(
        ca_specs={
            "FR01": (fr01_cert, fr01_leaf, fr01_expired),
            "FR06": (fr06_cert, fr06_leaf, fr06_expired),
        },
        tsl_next_update=now + dt.timedelta(days=180),
    )

    fetched: list[str] = []

    def fake_fetch(url: str, timeout: int = 10) -> bytes | None:
        fetched.append(url)
        assert "fr06" in url
        return fr06_fresh.public_bytes(Encoding.DER)

    monkeypatch.setattr(key_resolver_mod, "_fetch_bytes", fake_fetch)

    res = resolver.refresh_crls(ca_ids=["fr06", "FR99"])
    assert fetched == ["https://crl.example.gouv.fr/fr06.crl"]
    assert res == CrlRefreshResult(
        refreshed_cas=("FR06",),
        skipped_fresh_cas=(),
        failed_cas={"FR99": "unknown_ca"},
        expired_cas=(),
    )


def test_multi_cdp_url_falls_back_to_second_valid_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = dt.datetime.now(dt.UTC)
    ca_key, ca_cert = _build_ca(
        "CA FR06",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    url1 = "https://crl1.example.gouv.fr/fr06.crl"
    url2 = "https://crl2.example.gouv.fr/fr06.crl"
    _, leaf_cert = _build_leaf(
        "FPE2",
        ca_cert,
        ca_key,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=[url1, url2],
    )
    expired_crl = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(days=10),
        next_update=now - dt.timedelta(days=2),
    )
    fresh_crl = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(hours=1),
        next_update=now + dt.timedelta(days=5),
    )
    resolver = _make_resolver(
        ca_specs={"FR06": (ca_cert, leaf_cert, expired_crl)},
        tsl_next_update=now + dt.timedelta(days=180),
    )

    calls: list[str] = []

    def fake_fetch(url: str, timeout: int = 10) -> bytes | None:
        calls.append(url)
        if url == url1:
            return None
        return fresh_crl.public_bytes(Encoding.DER)

    monkeypatch.setattr(key_resolver_mod, "_fetch_bytes", fake_fetch)

    res = resolver.refresh_crls()
    assert calls == [url1, url2]
    assert res.refreshed_cas == ("FR06",)
    assert res.failed_cas == {}
    assert res.expired_cas == ()


def test_default_resolver_and_decode_never_make_implicit_network_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbid_network(*args: object, **kwargs: object) -> bytes | None:
        raise AssertionError("Aucun appel réseau implicite n'est autorisé !")

    monkeypatch.setattr(key_resolver_mod, "_fetch_bytes", forbid_network)
    reset_default_key_resolver()
    try:
        resolver = get_default_key_resolver()
        assert "FR06" in resolver.ca_ids

        # Un 2D-DOC minimal ne doit jamais déclencher d'appel réseau
        ec_key = ec.generate_private_key(ec.SECP256R1())
        raw = _build_signed_2ddoc(
            ca_id="FR06",
            cert_id="FPE2",
            issue_date=dt.date(2025, 1, 15),
            signature_date=dt.date(2025, 1, 15),
            private_key=ec_key,
        )
        decoded = decode_2d_doc(raw)
        assert decoded.verification is not None
    finally:
        reset_default_key_resolver()


def test_refresh_default_crls_delegates_to_default_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = dt.datetime.now(dt.UTC)
    ca_key, ca_cert = _build_ca(
        "CA FR06",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    crl_url = "https://crl.example.gouv.fr/fr06.crl"
    _, leaf_cert = _build_leaf(
        "FPE2",
        ca_cert,
        ca_key,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=[crl_url],
    )
    expired_crl = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(days=10),
        next_update=now - dt.timedelta(days=2),
    )
    fresh_crl = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(hours=1),
        next_update=now + dt.timedelta(days=5),
    )
    fake_default = _make_resolver(
        ca_specs={"FR06": (ca_cert, leaf_cert, expired_crl)},
        tsl_next_update=now + dt.timedelta(days=180),
    )

    monkeypatch.setattr(
        key_resolver_mod, "get_default_key_resolver", lambda: fake_default
    )
    monkeypatch.setattr(
        key_resolver_mod,
        "_fetch_bytes",
        lambda url, timeout=10: fresh_crl.public_bytes(Encoding.DER),
    )

    res = refresh_default_crls(ca_ids=["FR06"], timeout=5)
    assert res == CrlRefreshResult(
        refreshed_cas=("FR06",),
        skipped_fresh_cas=(),
        failed_cas={},
        expired_cas=(),
    )


def test_concurrent_refresh_and_verification_is_thread_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = dt.datetime.now(dt.UTC)
    ca_key, ca_cert = _build_ca(
        "CA FR06",
        not_before=now - dt.timedelta(days=365),
        not_after=now + dt.timedelta(days=365),
    )
    crl_url = "https://crl.example.gouv.fr/fr06.crl"
    leaf_key, leaf_cert = _build_leaf(
        "FPE2",
        ca_cert,
        ca_key,
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=365),
        crl_urls=[crl_url],
    )
    fresh_crl_1 = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(hours=2),
        next_update=now + dt.timedelta(days=5),
    )
    fresh_crl_2 = _build_crl(
        ca_cert,
        ca_key,
        last_update=now - dt.timedelta(hours=1),
        next_update=now + dt.timedelta(days=6),
    )
    fresh_der_2 = fresh_crl_2.public_bytes(Encoding.DER)

    resolver = _make_resolver(
        ca_specs={"FR06": (ca_cert, leaf_cert, fresh_crl_1)},
        tsl_next_update=now + dt.timedelta(days=180),
    )
    raw_doc = _build_signed_2ddoc(
        ca_id="FR06",
        cert_id="FPE2",
        issue_date=now.date(),
        signature_date=now.date(),
        private_key=leaf_key,
    )

    monkeypatch.setattr(
        key_resolver_mod, "_fetch_bytes", lambda url, timeout=10: fresh_der_2
    )

    barrier = threading.Barrier(8)
    errors: list[Exception] = []

    def worker(idx: int) -> None:
        try:
            barrier.wait()
            for _ in range(15):
                if idx % 2 == 0:
                    res = resolver.refresh_crls(only_expired=False)
                    assert res.refreshed_cas == ("FR06",)
                else:
                    decoded = decode_2d_doc(raw_doc, key_resolver=resolver)
                    assert decoded.is_valid is True
                    assert decoded.verification is not None
                    assert decoded.verification.status == VerificationStatus.VERIFIED
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))

    assert errors == []


def test_crl_refresh_result_is_frozen_and_validates_arguments() -> None:
    res = CrlRefreshResult(refreshed_cas=("FR06",))
    with pytest.raises(pydantic.ValidationError):
        res.refreshed_cas = ("FR07",)  # type: ignore[misc]

    resolver = KeyResolver()
    with pytest.raises(ValueError, match="timeout"):
        resolver.refresh_crls(timeout=0)
    with pytest.raises(ValueError, match="refresh_margin"):
        resolver.refresh_crls(refresh_margin=dt.timedelta(seconds=-1))
    with pytest.raises(ValueError, match="refresh_margin"):
        resolver.get_expired_crl_cas(refresh_margin=dt.timedelta(seconds=-1))
