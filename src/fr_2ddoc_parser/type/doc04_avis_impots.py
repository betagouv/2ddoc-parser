from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Dict, Literal, Optional, cast

from pydantic import BaseModel, Field

from fr_2ddoc_parser.model.models import Decoded2DDoc
from fr_2ddoc_parser.parser.helper import to_date_ddmmyyyy, to_dec, to_int
from fr_2ddoc_parser.registry.registry import register


# -----------------------------
# Avis d'imposition V1 (doc 04)
class AvisImpositionV1(BaseModel):
    """Modèle typé pour Avis d'impôt (04)."""

    doc_type: Literal["04"]
    nombre_de_parts: Decimal  # 43
    reference_avis: str  # 44
    annee_des_revenus: int  # 45
    declarant_1: str  # 46
    revenu_fiscal_de_reference: Optional[int] = None  # 41 (F)
    declarant_1_numero_fiscal: Optional[str] = None  # 47 (F)
    declarant_2: Optional[str] = None  # 48 (F)
    declarant_2_numero_fiscal: Optional[str] = None  # 49 (F)
    date_mise_en_recouvrement: Optional[date] = None  # 4A

    # Champs supplémentaires non cartographiés
    extras: Dict[str, str] = Field(default_factory=dict)

    # -------------------------
    # Construction depuis Decoded2DDoc
    @classmethod
    def from_decoded(cls, d: Decoded2DDoc) -> "AvisImpositionV1":
        f = d.fields
        known = {"41", "43", "44", "45", "46", "47", "48", "49", "4A"}

        extras = {k: v for k, v in f.items() if k not in known}

        obj = cls(
            doc_type=cast(Literal["04"], d.header.doc_type),
            revenu_fiscal_de_reference=to_int(f.get("41")),
            nombre_de_parts=cast(Decimal, to_dec(f.get("43")) or Decimal("0")),
            reference_avis=f.get("44", "").strip(),
            annee_des_revenus=cast(int, to_int(f.get("45")) or 0),
            declarant_1=f.get("46", "").strip(),
            declarant_1_numero_fiscal=f.get("47"),
            declarant_2=f.get("48"),
            declarant_2_numero_fiscal=f.get("49"),
            date_mise_en_recouvrement=to_date_ddmmyyyy(f.get("4A")),
            extras=extras,
        )
        # Ne pas utiliser la validation Pydantic pour les règles métier :
        # on conserve le comportement existant en appelant validate_required_fields() explicitement.
        obj.validate_required_fields()
        return obj

    # -------------------------
    # Validation des règles O / F
    def validate_required_fields(self) -> None:
        # Obligatoires
        if not self.nombre_de_parts:
            raise ValueError("Nombre de parts (43) est obligatoire.")
        if not self.reference_avis:
            raise ValueError("Référence d’avis (44) est obligatoire.")
        if not self.annee_des_revenus:
            raise ValueError("Année des revenus (45) est obligatoire.")
        if not self.declarant_1:
            raise ValueError("Déclarant 1 (46) est obligatoire.")
        if not self.date_mise_en_recouvrement:
            raise ValueError("Date de mise en recouvrement (4A) est obligatoire.")


# -----------------------------
# Handlers d’enregistrement
@register("04", "avis_imposition_v1")
def _handle_04(doc: Decoded2DDoc) -> AvisImpositionV1:
    return AvisImpositionV1.from_decoded(doc)
