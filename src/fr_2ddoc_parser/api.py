from __future__ import annotations
import importlib
import pkgutil
from typing import Optional

from fr_2ddoc_parser.crypto.key_resolver import local_key_resolver
from fr_2ddoc_parser.model.models import Decoded2DDoc
from fr_2ddoc_parser.parser.parser import parse
from fr_2ddoc_parser.registry.registry import get_handler, TypeHandler
from fr_2ddoc_parser.type.base import GenericDoc
import fr_2ddoc_parser.type as _types_pkg

_handlers_loaded = False


def _ensure_handlers_loaded():
    """Charge dynamiquement tous les modules de fr_2ddoc.types pour
    exécuter les décorateurs @register(...) et remplir le registre.

    Évite d'avoir à faire des imports explicites des handlers dans __init__.
    """
    global _handlers_loaded
    if _handlers_loaded:
        return
    for mod in pkgutil.iter_modules(_types_pkg.__path__):
        importlib.import_module(f"{_types_pkg.__name__}.{mod.name}")
    _handlers_loaded = True


def decode_2d_doc(data: str) -> Decoded2DDoc:
    """Decode un 2D-DOC DC04 depuis une chaîne lue (DataMatrix).

    Retourne un objet Decoded2DDoc avec :
      - header (DC04)
      - fields (dict id->valeur)
      - signature (bloc avec Base32 + bytes)
      - typed (si un handler de type est enregistré)
    """
    parsed_data = parse(data)
    _ensure_handlers_loaded()
    tuple: Optional[tuple[TypeHandler, str]] = get_handler(parsed_data.header.doc_type)
    detected_handler: Optional[TypeHandler] = None
    handler_name: Optional[str] = None
    if tuple is not None:
        detected_handler, handler_name = tuple
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
    try:
        parsed_data.verify(key_resolver=local_key_resolver)
    except Exception as e:
        print(f"Warning: signature verification failed: {e}")
        pass
    return parsed_data
