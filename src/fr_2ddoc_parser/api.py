from __future__ import annotations

import importlib
import logging
import pkgutil
from datetime import date

import fr_2ddoc_parser.type as _types_pkg
from fr_2ddoc_parser.crypto.key_resolver import (
    KeyResolver,
    get_default_key_resolver,
    refresh_default_crls,
)
from fr_2ddoc_parser.model.models import (
    CrlRefreshResult,
    Decoded2DDoc,
    VerificationResult,
    VerificationStatus,
)
from fr_2ddoc_parser.parser.parser import parse
from fr_2ddoc_parser.registry.registry import TypeHandler, get_handler
from fr_2ddoc_parser.type.base import GenericDoc

__all__ = [
    "CrlRefreshResult",
    "Decoded2DDoc",
    "VerificationResult",
    "VerificationStatus",
    "decode_2d_doc",
    "refresh_default_crls",
]

logger = logging.getLogger(__name__)

_handlers_loaded = False


def _ensure_handlers_loaded() -> None:
    """Charge dynamiquement tous les modules de fr_2ddoc_parser.type pour
    exécuter les décorateurs @register(...) et remplir le registre.

    Évite d'avoir à faire des imports explicites des handlers dans __init__.
    """
    global _handlers_loaded
    if _handlers_loaded:
        return
    for mod in pkgutil.iter_modules(_types_pkg.__path__):
        importlib.import_module(f"{_types_pkg.__name__}.{mod.name}")
    _handlers_loaded = True


def decode_2d_doc(
    data: str,
    *,
    key_resolver: KeyResolver | None = None,
    evaluation_date: date | None = None,
    strict_tsl_freshness: bool = True,
) -> Decoded2DDoc:
    """Décode et vérifie un 2D-DOC depuis une chaîne lue (DataMatrix).

    Retourne un objet ``Decoded2DDoc`` avec :
      - ``header`` (V02/V03/V04)
      - ``fields`` (dict id->valeur)
      - ``signature`` (bloc avec Base32 + bytes)
      - ``typed`` (modèle métier si un handler de type est enregistré)
      - ``verification`` (``VerificationResult`` détaillé)
      - ``is_valid`` (``True`` uniquement si ``verification.status == VERIFIED``)
    """
    parsed_data = parse(data)
    _ensure_handlers_loaded()
    handler_entry: tuple[TypeHandler, str] | None = get_handler(
        parsed_data.header.doc_type
    )
    detected_handler: TypeHandler | None = None
    handler_name: str | None = None
    if handler_entry is not None:
        detected_handler, handler_name = handler_entry
    if detected_handler:
        parsed_data.typed = detected_handler(parsed_data)
        parsed_data.ants_type = handler_name
    else:
        parsed_data.typed = GenericDoc(
            doc_type=parsed_data.header.doc_type,
            perimeter=parsed_data.header.perimeter,
            country=parsed_data.header.country,
            fields=parsed_data.fields,
        )

    resolver = key_resolver
    resolver_error: str | None = None
    if resolver is None:
        try:
            resolver = get_default_key_resolver()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Magasin de confiance par défaut indisponible: %s", exc)
            resolver_error = str(exc)

    result = parsed_data.verify(
        resolver,
        evaluation_date=evaluation_date,
        strict_tsl_freshness=strict_tsl_freshness,
    )
    if (
        resolver_error is not None
        and result.status == VerificationStatus.RESOLVER_UNAVAILABLE
    ):
        updated = VerificationResult(
            status=result.status,
            is_valid=result.is_valid,
            ca_id=result.ca_id,
            cert_id=result.cert_id,
            reference_date=result.reference_date,
            tsl_sequence_number=result.tsl_sequence_number,
            tsl_next_update=result.tsl_next_update,
            tsl_freshness=result.tsl_freshness,
            detail=resolver_error,
        )
        parsed_data.verification = updated
        result = updated

    if result.status != VerificationStatus.VERIFIED:
        logger.debug(
            "Vérification 2D-DOC non validée (status=%s, ca=%r, cert=%r): %s",
            result.status.value,
            result.ca_id,
            result.cert_id,
            result.detail,
        )

    return parsed_data
