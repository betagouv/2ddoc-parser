from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Dict, Literal, Optional, cast

from pydantic import BaseModel, Field, model_validator

from fr_2ddoc_parser.model.models import Decoded2DDoc
from fr_2ddoc_parser.parser.helper import (
    format_name,
    to_date_ddmmyyyy,
    to_date_hex,
    to_dec,
)
from fr_2ddoc_parser.registry.registry import register


# -----------------------------
# Bénéficiaire
class Beneficiaire(BaseModel):
    """Bénéficiaire du bulletin de salaire.
    Règle métier : 10 ou (12 et 13) obligatoire.
    """

    ligne1: Optional[str] = None  # 10
    qualite: Optional[str] = None  # 11
    prenom: Optional[str] = None  # 12
    nom: Optional[str] = None  # 13

    @model_validator(mode="after")
    def check_beneficiaire(self) -> "Beneficiaire":
        if not (self.ligne1 or (self.prenom and self.nom)):
            raise ValueError("Bénéficiaire invalide (ID 10 ou 12+13 obligatoire)")
        return self


# -----------------------------
# Bulletin de salaire (doc 06)
class BulletinSalaire(BaseModel):
    """Modèle typé pour Bulletin de salaire (06)."""

    doc_type: Literal["06"]
    beneficiaire: Beneficiaire

    siret_employeur: str  # 50 (O)
    debut_periode: date  # 53 (O)
    fin_periode: date  # 54 (O)
    debut_contrat: date  # 55 (O)
    salaire_net_imposable: Decimal  # 58 (O)
    cumul_salaire_net_imposable: Decimal  # 59 (O)

    nombre_heures_travaillees: Optional[Decimal] = None  # 51 (F)
    cumul_heures_travaillees: Optional[Decimal] = None  # 52 (F)
    date_signature_contrat: Optional[date] = None  # 57 (F)
    salaire_brut_mensuel: Optional[Decimal] = None  # 5A (F)
    denomination_sociale: Optional[str] = None  # 5M (F)
    nom_employeur: Optional[str] = None  # 5O (F)
    prenom_employeur: Optional[str] = None  # 5P (F)
    type_contrat: Optional[str] = None  # 5T (F)
    duree_contrat: Optional[str] = None  # 5U (F)

    # Champs supplémentaires non cartographiés
    extras: Dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_decoded(cls, d: Decoded2DDoc) -> "BulletinSalaire":
        f = d.fields
        benef = Beneficiaire(
            ligne1=f.get("10"),
            qualite=f.get("11"),
            prenom=f.get("12"),
            nom=f.get("13"),
        )
        known = {
            "10",
            "11",
            "12",
            "13",
            "50",
            "51",
            "52",
            "53",
            "54",
            "55",
            "57",
            "58",
            "59",
            "5A",
            "5M",
            "5O",
            "5P",
            "5T",
            "5U",
        }
        extras = {k: v for k, v in f.items() if k not in known}

        # Mapping pour 5T
        type_contrat_raw = f.get("5T")
        type_contrat_map = {"0": "CDD", "1": "CDI", "2": "CTT", "3": "CAP"}
        type_contrat = (
            type_contrat_map.get(type_contrat_raw) if type_contrat_raw else None
        )

        # On laisse Pydantic lever une ValidationError si les champs obligatoires sont None ou invalides
        return cls(
            doc_type=cast(Literal["06"], d.header.doc_type),
            beneficiaire=benef,
            siret_employeur=f.get("50"),
            debut_periode=to_date_hex(f.get("53")),
            fin_periode=to_date_hex(f.get("54")),
            debut_contrat=to_date_ddmmyyyy(f.get("55")),
            salaire_net_imposable=to_dec(f.get("58")),
            cumul_salaire_net_imposable=to_dec(f.get("59")),
            nombre_heures_travaillees=to_dec(f.get("51")),
            cumul_heures_travaillees=to_dec(f.get("52")),
            date_signature_contrat=to_date_ddmmyyyy(f.get("57")),
            salaire_brut_mensuel=to_dec(f.get("5A")),
            denomination_sociale=f.get("5M"),
            nom_employeur=f.get("5O"),
            prenom_employeur=f.get("5P"),
            type_contrat=type_contrat,
            duree_contrat=f.get("5U"),
            extras=extras,
        )

    @property
    def nom_beneficiaire(self) -> Optional[str]:
        if self.beneficiaire.ligne1:
            return format_name(self.beneficiaire.ligne1)
        if self.beneficiaire.nom:
            return f"{self.beneficiaire.nom} {self.beneficiaire.prenom or ''}".strip()
        return None


@register("06", "bulletin_salaire")
def _handle_06(doc: Decoded2DDoc) -> BulletinSalaire:
    return BulletinSalaire.from_decoded(doc)
