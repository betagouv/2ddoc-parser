# PKI Trust Establishment & Verification Architecture

This document describes the cryptographic trust establishment, certificate chain validation, revocation checking, and offline trust-store architecture implemented in `fr_2ddoc_parser` (resolving [`etalab-ia/document-ia#161`](https://github.com/etalab-ia/document-ia/issues/161)).

---

## 1. Threat Model & Design Rationale

In the French ANTS 2D-Doc specification, barcodes are signed by **participant (leaf) certificates** issued by **Certification Authorities (CAs)** listed in the ANTS **Trust Service Status List (TSL)**. Mathematical signature verification alone (`ECDSA` / `RSA`) is insufficient if the origin, chain of trust, validity period, and revocation status of the signing public key are not authenticated.

Previous revisions (`v1.0.6` / `31ce018`) exhibited six security and operational flaws:
1. **Implicit network calls at import time**: Importing `fr_2ddoc_parser.api` triggered outbound HTTP requests and HTML link scraping across third-party CA directories (`TSPInformationURI`), risking MITM tampering and startup timeouts in ephemeral container environments (e.g. Scalingo).
2. **Missing X.509 chain verification**: Downloaded leaf certificates were indexed without verifying `verify_directly_issued_by(ca_cert)`, `BasicConstraints`, `KeyUsage`, or `AuthorityKeyIdentifier`.
3. **Permissive ID derivation and unsafe single-cert fallback**: `_derive_cert_ids()` created truncation collisions, and `KeyResolver.resolve()` silently fell back to the single CA certificate in the TSL whenever a `cert_id` was unknown, masking unknown keys as invalid signatures.
4. **Unverified & stale TSL**: The XML-DSig/XAdES signature on `tsl_signed.xml` was never checked, and `<tsl:NextUpdate>` expiration was ignored.
5. **No CRL revocation or signing-time validity checks**: Revoked leaf certificates still published in CA directories were accepted, and temporal validity at the document's signature/issue date was ignored.
6. **Collapsed failure semantics**: All errors were flattened into `is_valid = False` with `print()` output, preventing callers from distinguishing forged signatures, untrusted certificates, unknown keys, stale trust lists, and unavailable trust stores.

---

## 2. Trust Chain & Offline Snapshot Architecture

### 2.1. Packaged Offline Trust Store (`src/fr_2ddoc_parser/crypto/keys/`)

Runtime verification performs **zero outbound network requests**. A cryptographically pre-verified trust snapshot (~470 KB total, containing exclusively public certificates and public CRLs) is bundled inside the Python package and loaded lazily on first use:

| Artifact | Purpose |
|---|---|
| `ants_tsl_root_ca.pem` | Trust anchor (`CN=Autorité de Certification Services Applicatifs`, `2.5.4.5=4`) used to authenticate the TSL signer (`CN=ANTS CACHET 2DDOC`). |
| `tsl_signed.xml` | Official ANTS ETSI TS 102 231 TSL (Sequence 23, `NextUpdate: 2027-05-11T14:00:00Z`), verified via XML-DSig on every load. |
| `trusted_leaves/<CA_ID>.pem` | Verified leaf certificates per active CA (`FR01`, `FR03`, `FR04`, `FR05`, `FR06`, `FR07`, `FR09`), excluding test CA `FR00`. |
| `crls/<CA_ID>.crl` | DER-encoded Certificate Revocation Lists signed by each CA. |

An external directory can override the bundled snapshot via the `FR_2DDOC_TRUST_STORE_DIR` environment variable or by passing an explicit `KeyResolver` instance to `decode_2d_doc(..., key_resolver=...)`.

### 2.2. Trust Store Lifecycle (`sync_trust_store`)

```mermaid
sequenceDiagram
    autonumber
    participant Ops as Operator / CI<br/>(sync_trust_store)
    participant ANTS as ANTS & CA Endpoints<br/>(TSL, Directories, CRLs)
    participant Val as trust_validator.py
    participant Store as Trust Store<br/>(crypto/keys/ or custom dir)
    participant Runtime as Runtime Worker<br/>(get_default_key_resolver)

    Note over Ops,Store: Explicit refresh (never run at import or runtime)
    Ops->>ANTS: Fetch tsl_signed.xml
    Ops->>Val: verify_tsl_xml_signature(xml, ants_tsl_root_ca.pem)
    Val-->>Ops: Authenticated TslMetadata (seq, issue_date, next_update)
    loop For each CA in TSL (excluding FR00)
        Ops->>ANTS: Fetch leaf directory & CDP CRLs
        Ops->>Val: validate_leaf_against_ca(leaf, ca_cert)
        Ops->>Val: validate_crl_against_ca(crl, ca_cert)
    end
    Ops->>Store: Stage in temp dir, validate KeyResolver.from_trust_store(), atomically promote

    Note over Store,Runtime: Runtime execution (zero network I/O)
    Runtime->>Store: Lazy-load via get_default_key_resolver()
    Runtime->>Val: Re-verify TSL XML-DSig + all CA->Leaf chains + CRL signatures
    Val-->>Runtime: Thread-safe singleton ready
```

---

## 3. Verification Decision Pipeline

When `decode_2d_doc()` or `Decoded2DDoc.verify()` executes, every verification passes through a strict ordered pipeline producing an immutable `VerificationResult`:

```mermaid
flowchart TD
    START["Decoded2DDoc"] --> SIG_PRES{"Signature present<br/>and Base32-decoded?"}
    SIG_PRES -- No --> ST_MISS["SIGNATURE_MISSING<br/>is_valid = False"]
    SIG_PRES -- Yes --> RES_AVAIL{"KeyResolver<br/>available?"}
    RES_AVAIL -- No --> ST_UNAVAIL["RESOLVER_UNAVAILABLE<br/>is_valid = False"]
    RES_AVAIL -- Yes --> TSL_FRESH{"strict_tsl_freshness<br/>and eval > NextUpdate?"}
    TSL_FRESH -- Yes --> ST_EXP["TRUST_LIST_EXPIRED<br/>tsl_freshness = STALE"]
    TSL_FRESH -- No --> CA_OK{"ca_id in TSL?"}
    CA_OK -- No --> ST_CA["UNKNOWN_CA<br/>is_valid = False"]
    CA_OK -- Yes --> CERT_OK{"(ca_id, cert_id) in<br/>validated leaf index?"}
    CERT_OK -- No --> ST_CERT["UNKNOWN_CERT<br/>is_valid = False"]
    CERT_OK -- Yes --> CHAIN_OK{"X.509 CA->Leaf chain<br/>& extensions valid?"}
    CHAIN_OK -- No --> ST_UNTR["UNTRUSTED_CERTIFICATE<br/>is_valid = False"]
    CHAIN_OK -- Yes --> CRL_OK{"Not revoked in<br/>CA CRL at ref_date?"}
    CRL_OK -- No --> ST_REV["CERT_REVOKED<br/>is_valid = False"]
    CRL_OK -- Yes --> DATE_OK{"Valid at ref_date<br/>(or eval_date if FFFF)?"}
    DATE_OK -- No --> ST_DATE["CERT_NOT_VALID_AT_SIGNING<br/>is_valid = False"]
    DATE_OK -- Yes --> MATH_OK{"ECDSA / RSA signature<br/>matches sign_payload?"}
    MATH_OK -- No --> ST_SIGINV["SIGNATURE_INVALID<br/>is_valid = False"]
    MATH_OK -- Yes --> ST_OK["VERIFIED<br/>is_valid = True"]
```

---

## 4. Security Controls Matrix

### 4.1. XML-DSig & XSW Hardening (`verify_tsl_xml_signature`)
- Rejects empty payloads and any `<!DOCTYPE` or `<!ENTITY` declaration before XML parsing.
- Enforces structural uniqueness: exactly one `<ds:Signature>` element whose direct parent is the root `<tsl:TrustServiceStatusList>` element (prevents XML Signature Wrapping attacks).
- Restricts algorithms to `RSA-SHA256/384/512`, `SHA-256/384/512` digests, and standard C14N / Exc-C14N canonicalization.
- Requires `<ds:Reference URI="">` covering the full document (minus `<ds:Signature>`) and verifies every `#id`-targeted `<ds:Reference>` (including `<xades:SignedProperties>`) using constant-time `hmac.compare_digest`.
- Verifies the TSL signer certificate directly against `ants_tsl_root_ca.pem` (`BasicConstraints.ca` must not be `True`; `KeyUsage.digital_signature` must hold if present; signer validity checked at `xades:SigningTime` or `tsl:ListIssueDateTime`).

### 4.2. X.509 Leaf & CRL Constraints (`validate_leaf_against_ca`, `validate_crl_against_ca`)
- Leaf certificate must satisfy `leaf_cert.verify_directly_issued_by(ca_cert)`.
- `BasicConstraints.ca` must be `False` (if extension present).
- `KeyUsage.digital_signature` must be `True` (extension required).
- `AuthorityKeyIdentifier.key_identifier` must match `ca_cert` `SubjectKeyIdentifier.digest` when both are present.
- `Subject` must contain a single `CommonName` (`CN`) matching `^[A-Za-z0-9]{4}$`, which serves as the sole authoritative `cert_id` lookup key (no heuristic truncation, no single-cert fallback).
- Each CRL must match `crl.issuer == ca_cert.subject`, pass `crl.is_signature_valid(ca_cert.public_key())`, and satisfy `last_update <= next_update`.

### 4.3. Temporal Validity & Revocation Rules
- **Reference date (`reference_date`)**: Derived from `header.signature_date` if present, else `header.issue_date`.
- **Historical validity**: If `reference_date` is present, both the leaf certificate and the CA certificate must be valid at `reference_date` (and `reference_date >= ca.status_start` when specified in the TSL). **A document validly signed in the past remains `VERIFIED` even if the certificate has since expired.**
- **Undated headers (`FFFF`)**: When both `signature_date` and `issue_date` are `None`, validity is evaluated against `evaluation_date` (default: current UTC date).
- **Revocation (`check_certificate_revocation`)**: A certificate listed in its CA's signed CRL is rejected with `CERT_REVOKED` when:
  - `reference_date is None`, OR
  - the CRL reason is `key_compromise` or `ca_compromise`, OR
  - `reference_date >= revocation_date`.
- **TSL Freshness (`strict_tsl_freshness`)**: By default (`strict_tsl_freshness=True`), evaluation past `tsl:NextUpdate` fails closed with `VerificationStatus.TRUST_LIST_EXPIRED` and `tsl_freshness = TrustListFreshness.STALE`.

---

## 5. Verification Status Reference

| `VerificationStatus` | `is_valid` | Meaning |
|---|---|---|
| `verified` | `True` | Signature valid, full TSL -> CA -> Leaf chain verified, non-revoked, valid at reference date, TSL fresh (or `strict_tsl_freshness=False`). |
| `signature_missing` | `False` | No signature block present in the 2D-Doc payload. |
| `signature_invalid` | `False` | Trusted leaf key found, but cryptographic verification failed (tampered payload or signature). |
| `unknown_ca` | `False` | Header `ca_id` is absent from the trusted TSL (including test CA `FR00`). |
| `unknown_cert` | `False` | Header `cert_id` has no validated leaf certificate under `ca_id`. |
| `untrusted_certificate` | `False` | Leaf certificate failed CA signature or X.509 constraint validation. |
| `cert_revoked` | `False` | Leaf certificate is revoked in its CA's signed CRL for the signing context. |
| `cert_not_valid_at_signing` | `False` | Reference date (or current date when `FFFF`) falls outside leaf/CA validity bounds. |
| `trust_list_expired` | `False` | TSL `NextUpdate` exceeded while `strict_tsl_freshness=True`. |
| `resolver_unavailable` | `False` | Trust store missing, unreadable, or failed integrity verification. |

---

## 6. Operational Usage & Refresh

### Synchronizing the Packaged or External Trust Store

```bash
# Refresh the packaged snapshot (development / release maintenance)
uv run python -m fr_2ddoc_parser.crypto.sync_trust_store

# Refresh an external mounted directory (e.g. runtime override via FR_2DDOC_TRUST_STORE_DIR)
uv run python -m fr_2ddoc_parser.crypto.sync_trust_store --output-dir /var/lib/2ddoc-trust-store
```

### Runtime Override Example

```python
from fr_2ddoc_parser.api import decode_2d_doc

result = decode_2d_doc(raw_2ddoc_string)
if result.verification is not None:
    print(
        result.verification.status,
        result.verification.tsl_freshness,
        result.verification.detail,
    )
```
