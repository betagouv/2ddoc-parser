from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Dict, Literal, Optional, cast

from pydantic import BaseModel, Field

from fr_2ddoc_parser.model.models import Decoded2DDoc
from fr_2ddoc_parser.parser.helper import (
    to_date_ddmmyyyy,
    to_date_hex,
    to_dec,
)
from fr_2ddoc_parser.registry.registry import register


class AttestationActiviteProfessionnelle(BaseModel):
    """Modèle typé pour Attestation d'Activité Professionnelle (29)."""

    doc_type: Literal["29"]

    # Champs obligatoires (O)
    siret_employeur: str  # 50
    date_debut_contrat: date  # 55
    periode_declaration_contrat: str  # 5V
    intitule_poste: str  # 5X
    liste_prenoms: str  # 60
    nom_patronymique: str  # 62
    date_naissance: date  # 69

    # Champs facultatifs (F)
    date_fin_contrat: Optional[date] = None  # 56
    denomination_sociale: Optional[str] = None  # 5M
    nature_contrat: Optional[str] = None  # 5W
    periode_remuneration: Optional[str] = None  # 5Y
    montant_remuneration: Optional[Decimal] = None  # 5Z

    # Champs supplémentaires non cartographiés
    extras: Dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_decoded(cls, d: Decoded2DDoc) -> AttestationActiviteProfessionnelle:
        f = d.fields
        known = {
            "50",
            "55",
            "56",
            "5M",
            "5V",
            "5W",
            "5X",
            "5Y",
            "5Z",
            "60",
            "62",
            "69",
        }
        extras = {k: v for k, v in f.items() if k not in known}

        # Conversion des dates (support ddmmyyyy et hex)
        date_debut = to_date_ddmmyyyy(f.get("55")) or to_date_hex(f.get("55"))
        date_fin = to_date_ddmmyyyy(f.get("56")) or to_date_hex(f.get("56"))
        date_naiss = to_date_ddmmyyyy(f.get("69")) or to_date_hex(f.get("69"))

        return cls(
            doc_type=cast(Literal["29"], d.header.doc_type),
            siret_employeur=f.get("50", ""),
            date_debut_contrat=cast(date, date_debut),
            periode_declaration_contrat=f.get("5V", ""),
            intitule_poste=f.get("5X", ""),
            liste_prenoms=f.get("60", ""),
            nom_patronymique=f.get("62", ""),
            date_naissance=cast(date, date_naiss),
            date_fin_contrat=date_fin,
            denomination_sociale=f.get("5M"),
            nature_contrat=f.get("5W"),
            periode_remuneration=f.get("5Y"),
            montant_remuneration=to_dec(f.get("5Z")),
            extras=extras,
        )

    @property
    def nom_complet_beneficiaire(self) -> Optional[str]:
        if self.nom_patronymique and self.liste_prenoms:
            return f"{self.nom_patronymique} {self.liste_prenoms}".strip()
        return self.nom_patronymique


@register("29", "attestation_activite_professionnelle")
def _handle_29(doc: Decoded2DDoc) -> AttestationActiviteProfessionnelle:
    return AttestationActiviteProfessionnelle.from_decoded(doc)
