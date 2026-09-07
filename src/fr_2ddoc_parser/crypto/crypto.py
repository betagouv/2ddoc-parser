from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# Les signatures 2D-DOC sont au format (r||s) en binaire. La lib cryptography
# attend ASN.1 DER (r,s). On convertit.


def _rs_concat_to_der(sig: bytes) -> bytes:
    if len(sig) % 2 != 0:
        raise ValueError("Signature (r||s) invalide")
    half = len(sig) // 2
    r = int.from_bytes(sig[:half], "big")
    s = int.from_bytes(sig[half:], "big")
    return encode_dss_signature(r, s)


def verify_signature(payload: bytes, signature_bytes: bytes, public_key: Any) -> bool:
    """
    Vérifie la signature d'un 2D-DOC.
    - EC : signature au format (r||s) -> convertie en DER puis ECDSA.
    - RSA: signature brute -> vérifiée en PKCS#1 v1.5 avec SHA-256/384/512 (on essaie).
    """
    # EC (ECDSA)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        # choisir le hash selon la courbe
        curve = public_key.curve
        if isinstance(curve, ec.SECP256R1):
            digest = hashes.SHA256()
        elif isinstance(curve, ec.SECP384R1):
            digest = hashes.SHA384()
        elif isinstance(curve, ec.SECP521R1):
            digest = hashes.SHA512()
        else:
            digest = hashes.SHA256()

        # (r||s) -> DER
        if len(signature_bytes) % 2 != 0:
            raise ValueError("Signature ECDSA (r||s) invalide")
        half = len(signature_bytes) // 2
        r = int.from_bytes(signature_bytes[:half], "big")
        s = int.from_bytes(signature_bytes[half:], "big")
        der = encode_dss_signature(r, s)

        try:
            public_key.verify(der, payload, ec.ECDSA(digest))
            return True
        except InvalidSignature:
            return False

    # RSA (PKCS#1 v1.5)
    if isinstance(public_key, rsa.RSAPublicKey):
        for digest in (hashes.SHA256(), hashes.SHA384(), hashes.SHA512()):
            try:
                public_key.verify(signature_bytes, payload, padding.PKCS1v15(), digest)
                return True
            except InvalidSignature:
                continue
        return False

    # Type de clé non géré
    raise TypeError(f"Unsupported public key type: {type(public_key)}")
