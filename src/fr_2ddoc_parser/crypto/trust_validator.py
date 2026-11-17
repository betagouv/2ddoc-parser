from __future__ import annotations

import base64
import hashlib
import hmac
import re
import warnings
import xml.dom.minidom as minidom
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import TypeVar
from xml.parsers.expat import ExpatError

import lxml.etree as LET
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
)

from fr_2ddoc_parser.exception.exceptions import (
    CertificateRevokedError,
    CertificateValidityError,
    ResolverUnavailableError,
    TrustSignatureError,
    UntrustedCertificateError,
)

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
TSL_NS = "http://uri.etsi.org/02231/v2#"
XADES_NS = "http://uri.etsi.org/01903/v1.3.2#"

_CERT_ID_RE = re.compile(r"^[A-Za-z0-9]{4}$")
_FORBIDDEN_XML_DECL_RE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)

_C14N_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
_C14N_INC = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
_XMLDSIG_FILTER2 = "http://www.w3.org/2002/06/xmldsig-filter2"
_ANTS_SUBTRACT_SIGNATURE_XPATH = "/descendant::ds:Signature"

_ALLOWED_C14N_ALGS = frozenset(
    {
        _C14N_EXC,
        _C14N_INC,
    }
)

_DIGEST_ALGS: dict[str, str] = {
    "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
}

_RSA_SIG_ALGS: dict[str, hashes.HashAlgorithm] = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": hashes.SHA256(),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": hashes.SHA384(),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": hashes.SHA512(),
}

_COMPROMISE_REASONS = frozenset(
    {
        x509.ReasonFlags.key_compromise,
        x509.ReasonFlags.ca_compromise,
    }
)

_ExtensionT = TypeVar("_ExtensionT", bound=x509.ExtensionType)


@dataclass(frozen=True)
class TslMetadata:
    """Métadonnées authentifiées extraites d'une TSL signée."""

    sequence_number: int | None
    issue_date: datetime | None
    next_update: datetime | None
    signer_cn: str | None


def _get_extension(
    cert: x509.Certificate, ext_class: type[_ExtensionT]
) -> _ExtensionT | None:
    """Lit une extension X.509 en filtrant l'avertissement RFC 5280 (>64 chars) de cryptography."""
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Attribute's length must be >= 1 and <= 64.*",
            category=UserWarning,
        )
        try:
            return cert.extensions.get_extension_for_class(ext_class).value
        except x509.ExtensionNotFound:
            return None


def _get_common_name(cert: x509.Certificate) -> str | None:
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Attribute's length must be >= 1 and <= 64.*",
            category=UserWarning,
        )
        attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not attrs:
        return None
    val = attrs[0].value
    return str(val) if val is not None else None


def extract_leaf_cert_id(cert: x509.Certificate) -> str:
    """Extrait strictement le cert_id (CommonName de 4 caractères alphanumériques)."""
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Attribute's length must be >= 1 and <= 64.*",
            category=UserWarning,
        )
        cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(cn_attrs) != 1:
        raise UntrustedCertificateError(
            "Le certificat feuille doit posséder exactement un attribut CommonName (CN)."
        )
    cn = str(cn_attrs[0].value or "").strip()
    if not _CERT_ID_RE.fullmatch(cn):
        raise UntrustedCertificateError(
            f"CommonName invalide pour un certificat feuille 2D-Doc: {cn!r} (4 caractères alphanumériques requis)."
        )
    return cn.upper()


def validate_leaf_against_ca(
    leaf_cert: x509.Certificate,
    ca_cert: x509.Certificate,
    *,
    expected_cert_id: str | None = None,
) -> str:
    """Valide cryptographiquement et structurellement un certificat feuille contre son AC.

    Vérifie :
      1. Signature directe par l'AC (``verify_directly_issued_by``).
      2. Contraintes d'AC sur ``ca_cert`` (``BasicConstraints.ca == True``, ``KeyUsage.key_cert_sign == True``).
      3. ``BasicConstraints.ca == False`` sur la feuille (si l'extension est présente).
      4. ``KeyUsage.digital_signature == True`` sur la feuille.
      5. Cohérence ``AuthorityKeyIdentifier == ca.SubjectKeyIdentifier`` (si présents).
      6. ``CommonName`` exact de 4 caractères alphanumériques.
    """
    ca_bc = _get_extension(ca_cert, x509.BasicConstraints)
    if ca_bc is None or not ca_bc.ca:
        raise UntrustedCertificateError(
            "Le certificat émetteur (AC) doit avoir BasicConstraints CA=True."
        )
    ca_ku = _get_extension(ca_cert, x509.KeyUsage)
    if ca_ku is None or not ca_ku.key_cert_sign:
        raise UntrustedCertificateError(
            "Le certificat émetteur (AC) doit autoriser keyCertSign."
        )

    try:
        leaf_cert.verify_directly_issued_by(ca_cert)
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise UntrustedCertificateError(
            f"Le certificat feuille n'est pas directement émis par l'AC attendue: {exc}"
        ) from exc

    basic_constraints = _get_extension(leaf_cert, x509.BasicConstraints)
    if basic_constraints is not None and basic_constraints.ca:
        raise UntrustedCertificateError(
            "Un certificat d'autorité (BasicConstraints CA=True) ne peut pas servir de certificat feuille."
        )

    key_usage = _get_extension(leaf_cert, x509.KeyUsage)
    if key_usage is None or not key_usage.digital_signature:
        raise UntrustedCertificateError(
            "Le certificat feuille ne possède pas l'usage de clé digitalSignature."
        )

    aki = _get_extension(leaf_cert, x509.AuthorityKeyIdentifier)
    ca_ski = _get_extension(ca_cert, x509.SubjectKeyIdentifier)
    if (
        aki is not None
        and aki.key_identifier is not None
        and ca_ski is not None
        and aki.key_identifier != ca_ski.digest
    ):
        raise UntrustedCertificateError(
            "Incohérence AuthorityKeyIdentifier / SubjectKeyIdentifier entre la feuille et son AC."
        )

    cert_id = extract_leaf_cert_id(leaf_cert)
    if expected_cert_id is not None and cert_id != expected_cert_id.upper():
        raise UntrustedCertificateError(
            f"CommonName du certificat ({cert_id}) différent du cert_id attendu ({expected_cert_id})."
        )
    return cert_id


def _parse_iso_datetime(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = raw.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _element_text(element: minidom.Element | None) -> str:
    if element is None:
        return ""
    parts: list[str] = []
    for child in element.childNodes:
        if isinstance(child, (minidom.Text, minidom.CDATASection)):
            parts.append(child.data)
    return "".join(parts).strip()


def _canonicalize_subtree(node: minidom.Element, *, exclusive: bool = True) -> bytes:
    """Canonicalise un sous-arbre avec C14N 1.0 inclusif ou exclusif via libxml2."""
    ns_map: dict[str, str] = {}
    xml_attributes: dict[str, str] = {}
    cur: minidom.Node | None = node
    while cur is not None and isinstance(cur, minidom.Element):
        if cur.attributes:
            for i in range(cur.attributes.length):
                attr = cur.attributes.item(i)
                if not isinstance(attr, minidom.Attr):
                    continue
                if attr.name.startswith("xmlns:") or attr.name == "xmlns":
                    ns_map.setdefault(attr.name, attr.value)
                elif not exclusive and attr.name.startswith("xml:"):
                    xml_attributes.setdefault(attr.name, attr.value)
        cur = cur.parentNode

    clone = node.cloneNode(deep=True)
    if not isinstance(clone, minidom.Element):
        raise TrustSignatureError("Noeud XML invalide lors de la canonicalisation.")
    for ns_attr, ns_value in sorted(ns_map.items()):
        if not clone.hasAttribute(ns_attr):
            clone.setAttribute(ns_attr, ns_value)
    for attr_name, attr_value in sorted(xml_attributes.items()):
        if not clone.hasAttribute(attr_name):
            clone.setAttribute(attr_name, attr_value)

    try:
        element = LET.fromstring(clone.toxml().encode("utf-8"))
    except LET.XMLSyntaxError as exc:
        raise TrustSignatureError(
            f"Noeud XML invalide lors de la canonicalisation: {exc}"
        ) from exc
    return LET.tostring(
        element,
        method="c14n",
        exclusive=exclusive,
        with_comments=False,
    )


def _canonicalize_document(document: minidom.Document, *, exclusive: bool) -> bytes:
    """Canonicalise le node-set document complet, y compris les PI hors racine."""
    try:
        root = LET.fromstring(document.toxml().encode("utf-8"))
    except LET.XMLSyntaxError as exc:
        raise TrustSignatureError(
            f"Document XML invalide lors de la canonicalisation: {exc}"
        ) from exc
    return LET.tostring(
        root.getroottree(),
        method="c14n",
        exclusive=exclusive,
        with_comments=False,
    )


def _canonicalize_subtree_exc(node: minidom.Element) -> bytes:
    """Alias rétrocompatible pour la canonicalisation C14N exclusive."""
    return _canonicalize_subtree(node, exclusive=True)


def _direct_children_ns(
    parent: minidom.Element, namespace: str, local_name: str
) -> list[minidom.Element]:
    out: list[minidom.Element] = []
    for child in parent.childNodes:
        if (
            isinstance(child, minidom.Element)
            and child.namespaceURI == namespace
            and child.localName == local_name
        ):
            out.append(child)
    return out


def _find_unique_element_by_id(
    root: minidom.Element, target_id: str
) -> minidom.Element:
    matches: list[minidom.Element] = []

    def _walk(el: minidom.Node) -> None:
        if not isinstance(el, minidom.Element):
            return
        for attr_name in ("Id", "ID", "id"):
            if el.hasAttribute(attr_name) and el.getAttribute(attr_name) == target_id:
                matches.append(el)
                break
        for child in el.childNodes:
            _walk(child)

    _walk(root)
    if len(matches) != 1:
        raise TrustSignatureError(
            f"Référence XML-DSig #{target_id} introuvable ou ambiguë ({len(matches)} occurrences)."
        )
    return matches[0]


def _lookup_namespace_uri(node: minidom.Element, prefix: str) -> str | None:
    attribute_name = f"xmlns:{prefix}" if prefix else "xmlns"
    cur: minidom.Node | None = node
    while cur is not None and isinstance(cur, minidom.Element):
        if cur.hasAttribute(attribute_name):
            return cur.getAttribute(attribute_name)
        cur = cur.parentNode
    return None


def _reject_unsupported_c14n_parameters(element: minidom.Element) -> None:
    if element.getAttribute("Algorithm") != _C14N_EXC:
        return
    if _direct_children_ns(element, _C14N_EXC, "InclusiveNamespaces"):
        raise TrustSignatureError(
            "Le paramètre Exclusive C14N InclusiveNamespaces/PrefixList n'est pas supporté."
        )


def _resolve_reference_profile(
    ref_el: minidom.Element,
    *,
    allow_enveloped: bool,
) -> tuple[bool, bool]:
    """Valide les transforms et retourne (C14N exclusif, suppression signature)."""
    transforms_els = _direct_children_ns(ref_el, DS_NS, "Transforms")
    if len(transforms_els) > 1:
        raise TrustSignatureError("ds:Transforms multiple dans ds:Reference.")

    algorithms: list[str] = []
    for transforms_el in transforms_els:
        for transform_el in _direct_children_ns(transforms_el, DS_NS, "Transform"):
            algorithm = transform_el.getAttribute("Algorithm")
            algorithms.append(algorithm)
            _reject_unsupported_c14n_parameters(transform_el)
            if algorithm == _XMLDSIG_FILTER2:
                xpath_els = _direct_children_ns(transform_el, _XMLDSIG_FILTER2, "XPath")
                if (
                    not allow_enveloped
                    or len(xpath_els) != 1
                    or xpath_els[0].getAttribute("Filter") != "subtract"
                    or _element_text(xpath_els[0]) != _ANTS_SUBTRACT_SIGNATURE_XPATH
                    or _lookup_namespace_uri(xpath_els[0], "ds") != DS_NS
                ):
                    raise TrustSignatureError(
                        "Seule la soustraction xmldsig-filter2 de /descendant::ds:Signature avec le namespace ds correct est supportée pour URI=''."
                    )

    allowed = {_ENVELOPED_SIGNATURE, _XMLDSIG_FILTER2, *_ALLOWED_C14N_ALGS}
    for algorithm in algorithms:
        if algorithm not in allowed:
            raise TrustSignatureError(
                f"Transform XML-DSig non supportée: {algorithm!r}"
            )
    if len(set(algorithms)) != len(algorithms):
        raise TrustSignatureError("Transform XML-DSig dupliquée dans ds:Reference.")
    if algorithms.count(_ENVELOPED_SIGNATURE) and not allow_enveloped:
        raise TrustSignatureError(
            "La transform enveloped-signature n'est supportée que pour URI=''."
        )
    signature_transforms = {_ENVELOPED_SIGNATURE, _XMLDSIG_FILTER2}
    for signature_transform in signature_transforms:
        if signature_transform in algorithms and algorithms[0] != signature_transform:
            raise TrustSignatureError(
                "La suppression de la signature doit précéder la canonicalisation."
            )

    c14n_algorithms = [alg for alg in algorithms if alg in _ALLOWED_C14N_ALGS]
    if len(c14n_algorithms) > 1:
        raise TrustSignatureError(
            "Plusieurs transforms C14N dans une même ds:Reference sont interdites."
        )
    if c14n_algorithms and algorithms[-1] != c14n_algorithms[0]:
        raise TrustSignatureError(
            "La canonicalisation doit être la dernière transform XML-DSig."
        )

    # Sans C14N explicite, XML-DSig convertit le node-set avec C14N 1.0 inclusif.
    exclusive = bool(c14n_algorithms and c14n_algorithms[0] == _C14N_EXC)
    remove_signature = any(alg in signature_transforms for alg in algorithms)
    return exclusive, remove_signature


def verify_tsl_xml_signature(
    xml_bytes: bytes,
    root_ca_cert: x509.Certificate,
    *,
    check_signer_validity: bool = True,
) -> TslMetadata:
    """Vérifie la signature XML-DSig et la chaîne de confiance d'une TSL ANTS.

    Protections appliquées :
      - Rejet immédiat de toute déclaration ``<!DOCTYPE`` ou ``<!ENTITY``.
      - Unicité et ancrage direct de ``<ds:Signature>`` sous la racine (anti-XSW).
      - Vérification du certificat signataire contre ``root_ca_cert`` (``KeyUsage``, ``AKI == SKI``).
      - Vérification des condensats SHA-256/384/512 de toutes les ``<ds:Reference>``.
      - Vérification de la signature RSA-SHA256/384/512 sur ``<ds:SignedInfo>``.
      - Validation obligatoire des métadonnées ``ListIssueDateTime`` et ``NextUpdate``.
    """
    if not xml_bytes or _FORBIDDEN_XML_DECL_RE.search(xml_bytes):
        raise TrustSignatureError(
            "Document XML TSL vide ou contenant une déclaration DOCTYPE/ENTITY interdite."
        )

    try:
        xml_text = xml_bytes.decode("utf-8")
        dom = minidom.parseString(xml_text)
    except (UnicodeDecodeError, ExpatError) as exc:
        raise TrustSignatureError(f"XML TSL mal formé: {exc}") from exc

    root = dom.documentElement
    if (
        root is None
        or root.namespaceURI != TSL_NS
        or root.localName != "TrustServiceStatusList"
    ):
        raise TrustSignatureError(
            "Racine XML TSL invalide (tsl:TrustServiceStatusList attendu)."
        )

    sigs = root.getElementsByTagNameNS(DS_NS, "Signature")
    if len(sigs) != 1 or sigs[0].parentNode is not root:
        raise TrustSignatureError(
            "La TSL doit contenir exactement un élément ds:Signature enfant direct de la racine."
        )
    sig_el = sigs[0]

    # Aucun élément du namespace TSL n'est autorisé à l'intérieur de ds:Signature (anti-XSW)
    if sig_el.getElementsByTagNameNS(TSL_NS, "*"):
        raise TrustSignatureError(
            "Élément TSL inattendu à l'intérieur de ds:Signature (XSW rejeté)."
        )

    signed_info_list = _direct_children_ns(sig_el, DS_NS, "SignedInfo")
    sig_val_list = _direct_children_ns(sig_el, DS_NS, "SignatureValue")
    key_info_list = _direct_children_ns(sig_el, DS_NS, "KeyInfo")
    if len(signed_info_list) != 1 or len(sig_val_list) != 1 or len(key_info_list) != 1:
        raise TrustSignatureError("Structure ds:Signature incomplète dans la TSL.")

    x509_data_list = _direct_children_ns(key_info_list[0], DS_NS, "X509Data")
    cert_els = (
        _direct_children_ns(x509_data_list[0], DS_NS, "X509Certificate")
        if x509_data_list
        else []
    )
    if not cert_els:
        raise TrustSignatureError(
            "Certificat signataire X509Certificate absent de ds:KeyInfo."
        )

    signed_info_el = signed_info_list[0]
    sig_val_b64 = _element_text(sig_val_list[0])
    signer_cert_b64 = _element_text(cert_els[0])
    try:
        signature_bytes = base64.b64decode(sig_val_b64, validate=True)
        signer_cert = x509.load_der_x509_certificate(
            base64.b64decode(signer_cert_b64, validate=True)
        )
    except Exception as exc:
        raise TrustSignatureError(
            f"Impossible de décoder la signature ou le certificat signataire TSL: {exc}"
        ) from exc

    # Chaîne signataire TSL -> Ancre ANTS
    try:
        signer_cert.verify_directly_issued_by(root_ca_cert)
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise TrustSignatureError(
            f"Le certificat signataire de la TSL n'est pas émis par l'ancre de confiance ANTS: {exc}"
        ) from exc

    signer_bc = _get_extension(signer_cert, x509.BasicConstraints)
    if signer_bc is not None and signer_bc.ca:
        raise TrustSignatureError(
            "Le certificat signataire TSL ne doit pas être une autorité de certification."
        )
    signer_ku = _get_extension(signer_cert, x509.KeyUsage)
    if signer_ku is None or not signer_ku.digital_signature:
        raise TrustSignatureError(
            "Le certificat signataire TSL doit posséder KeyUsage.digitalSignature."
        )

    signer_aki = _get_extension(signer_cert, x509.AuthorityKeyIdentifier)
    root_ski = _get_extension(root_ca_cert, x509.SubjectKeyIdentifier)
    if (
        signer_aki is not None
        and signer_aki.key_identifier is not None
        and root_ski is not None
        and signer_aki.key_identifier != root_ski.digest
    ):
        raise TrustSignatureError(
            "Incohérence AuthorityKeyIdentifier / SubjectKeyIdentifier entre le signataire TSL et l'ancre ANTS."
        )

    # Algorithmes autorisés (enfants directs de ds:SignedInfo)
    c14n_els = _direct_children_ns(signed_info_el, DS_NS, "CanonicalizationMethod")
    if len(c14n_els) != 1:
        raise TrustSignatureError(
            "ds:CanonicalizationMethod manquant ou multiple dans ds:SignedInfo."
        )
    c14n_alg = c14n_els[0].getAttribute("Algorithm")
    if c14n_alg not in _ALLOWED_C14N_ALGS:
        raise TrustSignatureError(
            f"Algorithme de canonicalisation TSL non supporté: {c14n_alg!r}"
        )
    _reject_unsupported_c14n_parameters(c14n_els[0])
    signed_info_exclusive = c14n_alg == _C14N_EXC

    sig_method_els = _direct_children_ns(signed_info_el, DS_NS, "SignatureMethod")
    if len(sig_method_els) != 1:
        raise TrustSignatureError("ds:SignatureMethod manquant dans ds:SignedInfo.")
    sig_alg = sig_method_els[0].getAttribute("Algorithm")
    rsa_hash = _RSA_SIG_ALGS.get(sig_alg)
    if rsa_hash is None:
        raise TrustSignatureError(
            f"Algorithme de signature TSL non autorisé: {sig_alg!r}"
        )

    # Vérification de toutes les références (enfants directs de ds:SignedInfo)
    ref_els = _direct_children_ns(signed_info_el, DS_NS, "Reference")
    if not ref_els:
        raise TrustSignatureError("Aucune référence ds:Reference dans ds:SignedInfo.")

    has_doc_ref = False
    verified_signed_props: list[minidom.Element] = []
    for ref_el in ref_els:
        uri = ref_el.getAttribute("URI")
        digest_method_els = _direct_children_ns(ref_el, DS_NS, "DigestMethod")
        digest_val_els = _direct_children_ns(ref_el, DS_NS, "DigestValue")
        if len(digest_method_els) != 1 or len(digest_val_els) != 1:
            raise TrustSignatureError("ds:Reference mal formée dans ds:SignedInfo.")

        digest_alg_uri = digest_method_els[0].getAttribute("Algorithm")
        hash_name = _DIGEST_ALGS.get(digest_alg_uri)
        if hash_name is None:
            raise TrustSignatureError(
                f"Algorithme de condensat TSL non autorisé: {digest_alg_uri!r}"
            )

        try:
            expected_digest = base64.b64decode(
                _element_text(digest_val_els[0]), validate=True
            )
        except Exception as exc:
            raise TrustSignatureError(f"DigestValue base64 invalide: {exc}") from exc

        ref_exclusive, remove_signature = _resolve_reference_profile(
            ref_el,
            allow_enveloped=uri == "",
        )

        target_el: minidom.Element | None = None
        if uri == "":
            has_doc_ref = True
            doc_clone = dom.cloneNode(deep=True)
            if (
                not isinstance(doc_clone, minidom.Document)
                or not doc_clone.documentElement
            ):
                raise TrustSignatureError("Clonage XML TSL impossible.")
            doc_root = doc_clone.documentElement
            doc_sigs = doc_root.getElementsByTagNameNS(DS_NS, "Signature")
            for ds_node in list(doc_sigs):
                if remove_signature and ds_node.parentNode is doc_root:
                    doc_root.removeChild(ds_node)
            c14n_bytes = _canonicalize_document(doc_clone, exclusive=ref_exclusive)
        elif uri.startswith("#"):
            target_el = _find_unique_element_by_id(root, uri[1:])
            c14n_bytes = _canonicalize_subtree(target_el, exclusive=ref_exclusive)
        else:
            raise TrustSignatureError(
                f"URI de référence XML-DSig non supportée: {uri!r}"
            )

        actual_digest = hashlib.new(hash_name, c14n_bytes).digest()
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise TrustSignatureError(
                f"Condensat XML-DSig invalide pour la référence {uri!r}."
            )
        if (
            target_el is not None
            and target_el.namespaceURI == XADES_NS
            and target_el.localName == "SignedProperties"
        ):
            verified_signed_props.append(target_el)

    if not has_doc_ref:
        raise TrustSignatureError(
            "La signature TSL doit couvrir l'ensemble du document (URI='')."
        )

    # Vérification cryptographique de SignedInfo
    signer_pub = signer_cert.public_key()
    if not isinstance(signer_pub, rsa.RSAPublicKey):
        raise TrustSignatureError(
            "La clé du certificat signataire TSL doit être une clé RSA."
        )

    c14n_signed_info = _canonicalize_subtree(
        signed_info_el, exclusive=signed_info_exclusive
    )
    try:
        signer_pub.verify(
            signature_bytes, c14n_signed_info, padding.PKCS1v15(), rsa_hash
        )
    except InvalidSignature as exc:
        raise TrustSignatureError(
            "Signature cryptographique XML-DSig de la TSL invalide."
        ) from exc

    # Extraction des métadonnées TSL uniquement depuis SchemeInformation (enfant direct de root)
    scheme_info_els = _direct_children_ns(root, TSL_NS, "SchemeInformation")
    if len(scheme_info_els) != 1:
        raise TrustSignatureError(
            "Élément tsl:SchemeInformation manquant ou multiple à la racine de la TSL."
        )
    scheme_info = scheme_info_els[0]

    seq_els = _direct_children_ns(scheme_info, TSL_NS, "TSLSequenceNumber")
    seq_num: int | None = None
    if seq_els:
        try:
            seq_num = int(_element_text(seq_els[0]))
        except ValueError:
            seq_num = None

    issue_els = _direct_children_ns(scheme_info, TSL_NS, "ListIssueDateTime")
    issue_date = _parse_iso_datetime(_element_text(issue_els[0])) if issue_els else None

    next_update: datetime | None = None
    next_els = _direct_children_ns(scheme_info, TSL_NS, "NextUpdate")
    if next_els:
        dt_els = _direct_children_ns(next_els[0], TSL_NS, "dateTime")
        if dt_els:
            next_update = _parse_iso_datetime(_element_text(dt_els[0]))

    if issue_date is None or next_update is None:
        raise TrustSignatureError(
            "Métadonnées TSL incomplètes ou invalides (ListIssueDateTime et NextUpdate requis)."
        )
    if issue_date > next_update:
        raise TrustSignatureError(
            f"Dates de la TSL incohérentes (ListIssueDateTime={issue_date} postérieur à NextUpdate={next_update})."
        )

    # SigningTime lu exclusivement depuis un <xades:SignedProperties> couvert par ds:Reference
    signing_time: datetime | None = None
    for sp_el in verified_signed_props:
        ssp_els = _direct_children_ns(sp_el, XADES_NS, "SignedSignatureProperties")
        if not ssp_els:
            continue
        st_els = _direct_children_ns(ssp_els[0], XADES_NS, "SigningTime")
        if st_els:
            signing_time = _parse_iso_datetime(_element_text(st_els[0]))
            if signing_time is not None:
                break

    if check_signer_validity:
        ref_dt = signing_time or issue_date
        if ref_dt is None:
            raise TrustSignatureError(
                "Impossible de vérifier la validité temporelle du signataire TSL (SigningTime et ListIssueDateTime absents)."
            )
        if not (
            signer_cert.not_valid_before_utc
            <= ref_dt
            <= signer_cert.not_valid_after_utc
        ):
            raise TrustSignatureError(
                "Le certificat signataire TSL n'était pas valide à la date de signature de la TSL."
            )
        if not (
            root_ca_cert.not_valid_before_utc
            <= ref_dt
            <= root_ca_cert.not_valid_after_utc
        ):
            raise TrustSignatureError(
                "L'ancre de confiance ANTS n'était pas valide à la date de signature de la TSL."
            )

    return TslMetadata(
        sequence_number=seq_num,
        issue_date=issue_date,
        next_update=next_update,
        signer_cn=_get_common_name(signer_cert),
    )


def validate_crl_against_ca(
    crl: x509.CertificateRevocationList, ca_cert: x509.Certificate
) -> None:
    """Vérifie l'émetteur, les contraintes d'AC, la signature et les dates d'une CRL."""
    ca_bc = _get_extension(ca_cert, x509.BasicConstraints)
    if ca_bc is None or not ca_bc.ca:
        raise TrustSignatureError(
            "Le certificat émetteur de la CRL doit avoir BasicConstraints CA=True."
        )
    ca_ku = _get_extension(ca_cert, x509.KeyUsage)
    if ca_ku is None or not ca_ku.crl_sign:
        raise TrustSignatureError(
            "Le certificat émetteur de la CRL doit autoriser cRLSign."
        )

    if crl.issuer != ca_cert.subject:
        raise TrustSignatureError(
            "L'émetteur de la CRL ne correspond pas au sujet de l'AC."
        )

    for extension in crl.extensions:
        if isinstance(extension.value, x509.DeltaCRLIndicator):
            raise TrustSignatureError(
                "Les CRLs delta ne sont pas supportées comme preuve complète de non-révocation."
            )
        if isinstance(extension.value, x509.IssuingDistributionPoint):
            raise TrustSignatureError(
                "Les CRLs avec IssuingDistributionPoint/partitionnement ne sont pas supportées comme preuve complète de non-révocation."
            )
        if extension.critical:
            raise TrustSignatureError(
                f"Extension critique CRL non supportée: {extension.oid.dotted_string}."
            )

    for revoked_certificate in crl:
        for extension in revoked_certificate.extensions:
            if extension.critical:
                raise TrustSignatureError(
                    "Extension critique d'entrée CRL non supportée pour le certificat série "
                    f"{revoked_certificate.serial_number}: {extension.oid.dotted_string}."
                )

    ca_pub = ca_cert.public_key()
    if not isinstance(
        ca_pub,
        (
            dsa.DSAPublicKey,
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
        ),
    ):
        raise TrustSignatureError(
            f"Type de clé publique AC non supporté pour la vérification CRL: {type(ca_pub)}"
        )
    try:
        is_valid = crl.is_signature_valid(ca_pub)
    except Exception as exc:
        raise TrustSignatureError(
            f"Impossible de vérifier la signature de la CRL: {exc}"
        ) from exc

    if not is_valid:
        raise TrustSignatureError(
            "Signature cryptographique de la CRL invalide pour cette AC."
        )

    if crl.next_update_utc is not None and crl.last_update_utc > crl.next_update_utc:
        raise TrustSignatureError(
            "Dates de la CRL incohérentes (last_update postérieur à next_update)."
        )


def is_crl_applicable(
    crl: x509.CertificateRevocationList,
    evaluation_date: date | None = None,
) -> bool:
    """Indique si une CRL est applicable à l'instant ou à la date d'évaluation."""
    last_update = crl.last_update_utc
    next_update = crl.next_update_utc
    if last_update is None or next_update is None:
        return False
    if evaluation_date is not None:
        return last_update.date() <= evaluation_date <= next_update.date()
    now = datetime.now(timezone.utc)
    return last_update <= now <= next_update


def check_certificate_revocation(
    leaf_cert: x509.Certificate,
    crls: Sequence[x509.CertificateRevocationList],
    reference_date: date | None,
    evaluation_date: date | None = None,
) -> None:
    """Contrôle la révocation avec des CRLs applicables à l'évaluation.

    En l'absence de CRL courante, la preuve de non-révocation est indisponible et
    la vérification échoue fermée avec ``ResolverUnavailableError``.
    Un certificat listé est rejeté si ``reference_date`` est absente, si la raison
    est une compromission, ou si ``reference_date >= revocation_date``.
    """
    applicable_crls = [crl for crl in crls if is_crl_applicable(crl, evaluation_date)]
    if not applicable_crls:
        raise ResolverUnavailableError(
            "Aucune CRL applicable à la date d'évaluation pour ce certificat."
        )

    for crl in applicable_crls:
        revoked = crl.get_revoked_certificate_by_serial_number(leaf_cert.serial_number)
        if revoked is None:
            continue

        reason: x509.ReasonFlags | None = None
        try:
            reason_ext = revoked.extensions.get_extension_for_class(x509.CRLReason)
            reason = reason_ext.value.reason
        except x509.ExtensionNotFound:
            reason = None

        rev_date = revoked.revocation_date_utc.date()
        is_compromise = reason in _COMPROMISE_REASONS
        if reference_date is None or is_compromise or reference_date >= rev_date:
            raise CertificateRevokedError(
                f"Certificat série {leaf_cert.serial_number} révoqué le {rev_date.isoformat()}."
            )


def _to_utc_date(value: datetime) -> date:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc).date()
    return value.astimezone(timezone.utc).date()


def validate_certificate_dates(
    leaf_cert: x509.Certificate,
    ca_cert: x509.Certificate,
    *,
    reference_date: date | None,
    evaluation_date: date,
    ca_status_start: datetime | None = None,
) -> None:
    """Vérifie la validité temporelle de la feuille et de l'AC à ``reference_date``.

    Si ``reference_date`` est défini (``signature_date`` ou ``issue_date``) :
      un certificat expiré aujourd'hui mais valide à ``reference_date`` est ACCEPTÉ
      (sous réserve de ``PrivateKeyUsagePeriod`` si présente sur la feuille).
    Si ``reference_date`` est ``None`` (``FFFF``) :
      vérifie la validité à ``evaluation_date`` (date courante UTC par défaut).
    """
    del ca_status_start  # Conservé uniquement pour compatibilité d'appel et tri TSL.
    check_date = reference_date if reference_date is not None else evaluation_date

    leaf_start = leaf_cert.not_valid_before_utc.date()
    leaf_end = leaf_cert.not_valid_after_utc.date()
    if not (leaf_start <= check_date <= leaf_end):
        raise CertificateValidityError(
            f"Certificat feuille hors période de validité [{leaf_start}, {leaf_end}] pour la date {check_date}."
        )

    ca_start = ca_cert.not_valid_before_utc.date()
    ca_end = ca_cert.not_valid_after_utc.date()
    if not (ca_start <= check_date <= ca_end):
        raise CertificateValidityError(
            f"Certificat AC hors période de validité [{ca_start}, {ca_end}] pour la date {check_date}."
        )

    if reference_date is not None:
        pkup = _get_extension(leaf_cert, x509.PrivateKeyUsagePeriod)
        if pkup is not None:
            if pkup.not_before is not None:
                pk_start = _to_utc_date(pkup.not_before)
                if reference_date < pk_start:
                    raise CertificateValidityError(
                        f"Clé privée utilisée avant PrivateKeyUsagePeriod.not_before ({pk_start}) pour la date {reference_date}."
                    )
            if pkup.not_after is not None:
                pk_end = _to_utc_date(pkup.not_after)
                if reference_date > pk_end:
                    raise CertificateValidityError(
                        f"Clé privée utilisée après PrivateKeyUsagePeriod.not_after ({pk_end}) pour la date {reference_date}."
                    )
