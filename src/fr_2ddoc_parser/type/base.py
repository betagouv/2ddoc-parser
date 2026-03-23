from __future__ import annotations

from typing import Dict
from pydantic import BaseModel


class GenericDoc(BaseModel):
    """Fallback si aucun modèle dédié n'est déclaré pour doc_type."""

    doc_type: str
    perimeter: str
    country: str
    fields: Dict[str, str]
