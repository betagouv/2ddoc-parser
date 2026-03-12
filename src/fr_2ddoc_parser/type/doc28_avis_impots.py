from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Dict, Literal, Optional, cast

from pydantic import BaseModel, Field

from fr_2ddoc_parser.model.models import Decoded2DDoc
from fr_2ddoc_parser.parser.helper import to_date_ddmmyyyy, to_dec, to_int
from fr_2ddoc_parser.registry.registry import register


# -----------------------------
# Adresse — règle O(1)/O(2)
class AdresseImposition(BaseModel):
    """Adresse pour avis d'imposition (docs 28).
    O(1)  : 4Y (adresse complète) obligatoire si on ne peut pas suivre la norme postale.
    O(2)  : 6U/6W/6X/6Y obligatoires si on suit la norme postale (4Y devient alors facultatif).
    6V (complément) reste facultatif.
    """

    full: Optional[str] = None  # 4Y
    voie: Optional[str] = None  # 6U
    complement: Optional[str] = None  # 6V
    code_postal: Optional[str] = None  # 6W
    commune: Optional[str] = None  # 6X
    pays: Optional[str] = None  # 6Y

    def is_ok_28(self) -> bool:
        struct_ok = bool(self.voie and self.code_postal and self.commune and self.pays)
        return bool(self.full) or struct_ok


# -----------------------------
# Avis d'imposition (doc 28)
class AvisImposition(BaseModel):
    """Modèle typé pour Avis d'impôt (28)."""

    doc_type: Literal["28"]
    nombre_de_parts: Decimal  # 43
    reference_avis: str  # 44
    annee_des_revenus: int  # 45
    declarant_1: str  # 46
    revenu_fiscal_de_reference: Optional[int] = None  # 41 (F)
    declarant_1_numero_fiscal: Optional[str] = None  # 47 (F)
    declarant_2: Optional[str] = None  # 48 (F)
    declarant_2_numero_fiscal: Optional[str] = None  # 49 (F)
    date_mise_en_recouvrement: Optional[date] = None  # 4A
    impot_revenu_net: Optional[int] = None  # 4V (F)
    reste_a_payer: Optional[int] = None  # 4W (F)
    retenue_a_la_source: Optional[int] = None  # 4X (F)

    adresse: AdresseImposition = Field(default_factory=AdresseImposition)

    # Champs supplémentaires non cartographiés
    extras: Dict[str, str] = Field(default_factory=dict)

    # -------------------------
    # Construction depuis Decoded2DDoc
    @classmethod
    def from_decoded(cls, d: Decoded2DDoc) -> "AvisImposition":
        f = d.fields
        adresse = AdresseImposition(
            full=f.get("4Y"),
            voie=f.get("6U"),
            complement=f.get("6V"),
            code_postal=f.get("6W"),
            commune=f.get("6X"),
            pays=f.get("6Y"),
        )
        known = {
            "41",
            "43",
            "44",
            "45",
            "46",
            "47",
            "48",
            "49",
            "4A",
            "4V",
            "4W",
            "4X",
            "4Y",
            "6U",
            "6V",
            "6W",
            "6X",
            "6Y",
        }

        extras = {k: v for k, v in f.items() if k not in known}

        obj = cls(
            doc_type=cast(Literal["28"], d.header.doc_type),
            revenu_fiscal_de_reference=to_int(f.get("41")),
            nombre_de_parts=cast(Decimal, to_dec(f.get("43")) or Decimal("0")),
            reference_avis=f.get("44", "").strip(),
            annee_des_revenus=cast(int, to_int(f.get("45")) or 0),
            declarant_1=f.get("46", "").strip(),
            declarant_1_numero_fiscal=f.get("47"),
            declarant_2=f.get("48"),
            declarant_2_numero_fiscal=f.get("49"),
            date_mise_en_recouvrement=to_date_ddmmyyyy(f.get("4A")),
            impot_revenu_net=to_int(f.get("4V")),
            reste_a_payer=to_int(f.get("4W")),
            retenue_a_la_source=to_int(f.get("4X")),
            adresse=adresse,
            extras=extras,
        )
        # Ne pas utiliser la validation Pydantic pour les règles métier :
        # on conserve le comportement existant en appelant validate_required_fields() explicitement.
        obj.validate_required_fields()
        return obj

    # -------------------------
    # Validation des règles O / F + O(1)/O(2)
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
        if not self.adresse.is_ok_28():
            raise ValueError("Adresse invalide : fournir 4Y ou bien 6U+6W+6X+6Y.")


# -----------------------------
# Handlers d’enregistrement
@register("28", "avis_imposition")
def _handle_28(doc: Decoded2DDoc) -> AvisImposition:
    return AvisImposition.from_decoded(doc)
