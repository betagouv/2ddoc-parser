class TwoDDocError(Exception):
    """Erreur générique 2D-DOC."""


class TwoDDocFormatError(TwoDDocError):
    """Chaîne 2D-DOC mal formée."""


class TwoDDocUnsupportedVersion(TwoDDocError):
    """Version d'en-tête non supportée par ce parseur (DC04 uniquement)."""


class TwoDDocSignatureError(TwoDDocError):
    """Signature invalide ou introuvable."""


class TwoDDocTrustError(TwoDDocError):
    """Erreur générique liée à l'établissement de confiance PKI."""


class UnknownCAError(TwoDDocTrustError):
    """Autorité de Certification (ca_id) absente de la TSL de confiance."""


class UnknownCertificateError(TwoDDocTrustError):
    """Certificat (cert_id) introuvable pour cette Autorité de Certification."""


class UntrustedCertificateError(TwoDDocTrustError):
    """Certificat non signé par l'AC ou non conforme aux contraintes X.509."""


class CertificateRevokedError(TwoDDocTrustError):
    """Certificat feuille révoqué dans la CRL signée de son AC."""


class CertificateValidityError(TwoDDocTrustError):
    """Certificat hors période de validité à la date de signature/référence."""


class TrustListExpiredError(TwoDDocTrustError):
    """Liste de confiance (TSL) périmée (NextUpdate dépassé)."""


class TrustSignatureError(TwoDDocTrustError):
    """Signature de la TSL ou d'une CRL invalide ou non ancrée."""


class ResolverUnavailableError(TwoDDocTrustError):
    """Magasin de confiance indisponible, manquant ou corrompu."""
