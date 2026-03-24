from __future__ import annotations

from typing import Callable, Dict, Optional, Any
from pydantic import BaseModel

from fr_2ddoc_parser.model.models import Decoded2DDoc

# Définition d'un 'type handler' : transforme un Decoded2DDoc -> objet typé
TypeHandler = Callable[[Decoded2DDoc], Any]


class TypeInfo(BaseModel):
    code: str
    name: str
    handler: TypeHandler


class TypeRegistry:
    def __init__(self):
        self._handlers: Dict[str, tuple[TypeHandler, str]] = {}

    def register(self, code: str, handler: TypeHandler, name: str):
        self._handlers[code.upper()] = (handler, name)

    def get(self, code: str) -> Optional[tuple[TypeHandler, str]]:
        return self._handlers.get(code.upper())


# Registre global simple
_registry = TypeRegistry()


def register(code: str, name: str):
    def deco(fn: TypeHandler):
        _registry.register(code, fn, name)
        return fn

    return deco


def get_handler(code: str) -> Optional[tuple[TypeHandler, str]]:
    return _registry.get(code)
