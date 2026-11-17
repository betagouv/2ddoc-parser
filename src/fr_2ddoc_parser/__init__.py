from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fr_2ddoc_parser.crypto.key_resolver import refresh_keys

__all__ = ["refresh_keys"]


def __getattr__(name: str) -> Any:
    if name == "refresh_keys":
        from fr_2ddoc_parser.crypto.key_resolver import refresh_keys

        return refresh_keys
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
