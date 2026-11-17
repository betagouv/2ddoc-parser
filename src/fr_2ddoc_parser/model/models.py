from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from fr_2ddoc_parser.crypto.crypto import verify_signature
from fr_2ddoc_parser.exception.exceptions import (
    CertificateRevokedError,
    CertificateValidityError,
    ResolverUnavailableError,
    TrustListExpiredError,
    TrustSignatureError,
    TwoDDocSignatureError,
    UnknownCAError,
    UnknownCertificateError,
    UntrustedCertificateError,
)
from fr_2ddoc_parser.type.base import GenericDoc

if TYPE_CHECKING:
    from fr_2ddoc_parser.crypto.key_resolver import KeyResolver

GS = "\x1d"  # Group Separator (sépare les paires champ/valeur)
US = "\x1f"  # Unit Separator (sépare les données de la signature)


class VerificationStatus(str, Enum):
    """Statut détaillé de la vérification cryptographique et PKI d'un 2D-DOC."""

    VERIFIED = "verified"
    SIGNATURE_MISSING = "signature_missing"
    SIGNATURE_INVALID = "signature_invalid"
    UNKNOWN_CA = "unknown_ca"
    UNKNOWN_CERT = "unknown_cert"
    UNTRUSTED_CERTIFICATE = "untrusted_certificate"
    CERT_REVOKED = "cert_revoked"
    CERT_NOT_VALID_AT_SIGNING = "cert_not_valid_at_signing"
    TRUST_LIST_EXPIRED = "trust_list_expired"
    RESOLVER_UNAVAILABLE = "resolver_unavailable"


class TrustListFreshness(str, Enum):
    """État de fraîcheur de la liste de confiance (TSL)."""

    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


class VerificationResult(BaseModel):
    """Résultat détaillé et immuable de la vérification d'un 2D-DOC."""

    model_config = ConfigDict(frozen=True)

    status: VerificationStatus
    is_valid: bool
    ca_id: str | None = None
    cert_id: str | None = None
    reference_date: date | None = None
    tsl_sequence_number: int | None = None
    tsl_next_update: datetime | None = None
    tsl_freshness: TrustListFreshness = TrustListFreshness.UNKNOWN
    detail: str | None = None


class Header(BaseModel):
    model_config = ConfigDict(frozen=True)

    raw: str
    marker: str
    version: int
    ca_id: str
    cert_id: str
    issue_date: date | None
    signature_date: date | None
    doc_type: str
    perimeter: str
    country: str | None = None
    header_len: int = 0


class SignatureBlock(BaseModel):
    present: bool = False
    b32: str | None = None
    raw: bytes | None = None  # décodée en bytes
    alg_hint: str | None = None  # "P-256"/"P-384"/"P-521" if detectable


class Decoded2DDoc(BaseModel):
    header: Header
    # Données brutes "avant US" (sert au hash/verify)
    sign_payload: bytes
    # Paires ID -> valeur (après parsing des segments GS)
    fields: dict[str, str] = Field(default_factory=dict)
    # Variante typée (si un modèle dédié existe pour ce type)
    typed: BaseModel | GenericDoc | None = None
    signature: SignatureBlock = Field(
        default_factory=lambda: SignatureBlock(present=False)
    )
    is_valid: bool = False
    verification: VerificationResult | None = None
    ants_type: str | None = None

    def verify(
        self,
        key_resolver: KeyResolver | None,
        *,
        evaluation_date: date | None = None,
        strict_tsl_freshness: bool = True,
    ) -> VerificationResult:
        """Vérifie la signature et la chaîne de confiance PKI du 2D-DOC.

        Met à jour ``self.verification`` et ``self.is_valid`` puis retourne
        le ``VerificationResult`` détaillé.
        """
        reference_date = self.header.signature_date or self.header.issue_date
        effective_eval_date = evaluation_date or datetime.now(timezone.utc).date()

        tsl_seq: int | None = None
        tsl_next: datetime | None = None
        tsl_fresh = TrustListFreshness.UNKNOWN

        if key_resolver is not None:
            tsl_seq = getattr(key_resolver, "tsl_sequence_number", None)
            tsl_next = getattr(key_resolver, "tsl_next_update", None)
            get_freshness = getattr(key_resolver, "get_tsl_freshness", None)
            if callable(get_freshness):
                raw_freshness = get_freshness(evaluation_date=evaluation_date)
                if isinstance(raw_freshness, TrustListFreshness):
                    tsl_fresh = raw_freshness
                elif isinstance(raw_freshness, str):
                    try:
                        tsl_fresh = TrustListFreshness(raw_freshness)
                    except ValueError:
                        tsl_fresh = TrustListFreshness.UNKNOWN

        def _finish(
            status: VerificationStatus, detail: str | None = None
        ) -> VerificationResult:
            result = VerificationResult(
                status=status,
                is_valid=(status == VerificationStatus.VERIFIED),
                ca_id=self.header.ca_id,
                cert_id=self.header.cert_id,
                reference_date=reference_date,
                tsl_sequence_number=tsl_seq,
                tsl_next_update=tsl_next,
                tsl_freshness=tsl_fresh,
                detail=detail,
            )
            self.verification = result
            self.is_valid = result.is_valid
            return result

        if not self.signature.present or not self.signature.raw:
            return _finish(
                VerificationStatus.SIGNATURE_MISSING,
                "Pas de signature présente dans ce 2D-DOC.",
            )

        if key_resolver is None:
            return _finish(
                VerificationStatus.RESOLVER_UNAVAILABLE,
                "Magasin de confiance (KeyResolver) indisponible.",
            )

        try:
            resolve_fn = getattr(key_resolver, "resolve_for_verification", None)
            if callable(resolve_fn):
                ctx = key_resolver.resolve_for_verification(
                    self.header.ca_id,
                    self.header.cert_id,
                    reference_date=reference_date,
                    evaluation_date=effective_eval_date,
                    tsl_eval_date=evaluation_date,
                    strict_tsl_freshness=strict_tsl_freshness,
                )
                pub = ctx.leaf_cert.public_key()
            else:
                pub = key_resolver.resolve(self.header.ca_id, self.header.cert_id)
        except TrustListExpiredError as exc:
            return _finish(VerificationStatus.TRUST_LIST_EXPIRED, str(exc))
        except UnknownCAError as exc:
            return _finish(VerificationStatus.UNKNOWN_CA, str(exc))
        except (UnknownCertificateError, KeyError) as exc:
            return _finish(VerificationStatus.UNKNOWN_CERT, str(exc))
        except UntrustedCertificateError as exc:
            return _finish(VerificationStatus.UNTRUSTED_CERTIFICATE, str(exc))
        except CertificateRevokedError as exc:
            return _finish(VerificationStatus.CERT_REVOKED, str(exc))
        except CertificateValidityError as exc:
            return _finish(VerificationStatus.CERT_NOT_VALID_AT_SIGNING, str(exc))
        except (ResolverUnavailableError, TrustSignatureError) as exc:
            return _finish(VerificationStatus.RESOLVER_UNAVAILABLE, str(exc))

        try:
            sig_ok = verify_signature(self.sign_payload, self.signature.raw, pub)
        except (ValueError, TypeError, TwoDDocSignatureError) as exc:
            return _finish(VerificationStatus.SIGNATURE_INVALID, str(exc))

        if not sig_ok:
            return _finish(
                VerificationStatus.SIGNATURE_INVALID,
                "La signature cryptographique ne correspond pas aux données.",
            )

        return _finish(VerificationStatus.VERIFIED)
