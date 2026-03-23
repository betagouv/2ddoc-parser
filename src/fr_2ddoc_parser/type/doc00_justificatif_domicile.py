from __future__ import annotations

from typing import Dict, Literal, Optional, cast

from fr_2ddoc_parser.model.models import Decoded2DDoc
from fr_2ddoc_parser.parser.helper import format_name
from fr_2ddoc_parser.registry.registry import register
from pydantic import BaseModel, Field


class JustificatifDomicile(BaseModel):
    """Modèle typé pour Justificatif de domicile (00)."""

    doc_type: Literal["00"]

    id_document: Optional[str] = (
        None  # 01 (F) - Présent dans certains exemples, mais pas dans la doc. On le rend optionnel.
    )
    # Bénéficiaire
    ligne1: Optional[str] = None  # 10 (O*)
    qualite: Optional[str] = None  # 11 (O*)
    prenom: Optional[str] = None  # 12 (O*)
    nom: Optional[str] = None  # 13 (O*)

    # Co-bénéficiaire
    co_beneficiaire_present: Optional[str] = None  # 1G (F)
    co_ligne1: Optional[str] = None  # 1I (F)
    co_qualite: Optional[str] = None  # 1J (F)
    co_prenom: Optional[str] = None  # 1K (F)
    co_nom: Optional[str] = None  # 1L (F)

    # Adresse
    ligne2: Optional[str] = None  # 20 (O)
    ligne3: Optional[str] = None  # 21 (O)
    voie: Optional[str] = None  # 22 (O)
    ligne5: Optional[str] = None  # 23 (O)
    code_postal: Optional[str] = None  # 24 (O)
    localite: Optional[str] = None  # 25 (O)
    pays: Optional[str] = None  # 26 (O)

    # Champs supplémentaires non cartographiés
    extras: Dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_decoded(cls, d: Decoded2DDoc) -> "JustificatifDomicile":
        f = d.fields
        known = {
            "01",
            "10",
            "11",
            "12",
            "13",
            "1G",
            "1I",
            "1J",
            "1K",
            "1L",
            "20",
            "21",
            "22",
            "23",
            "24",
            "25",
            "26",
        }
        extras = {k: v for k, v in f.items() if k not in known}

        obj = cls(
            doc_type=cast(Literal["00"], d.header.doc_type),
            id_document=f.get("01"),
            ligne1=format_name(f.get("10")),
            qualite=format_name(f.get("11")),
            prenom=format_name(f.get("12")),
            nom=format_name(f.get("13")),
            co_beneficiaire_present=f.get("1G"),
            co_ligne1=format_name(f.get("1I")),
            co_qualite=format_name(f.get("1J")),
            co_prenom=format_name(f.get("1K")),
            co_nom=format_name(f.get("1L")),
            ligne2=f.get("20"),
            ligne3=f.get("21"),
            voie=f.get("22"),
            ligne5=f.get("23"),
            code_postal=f.get("24"),
            localite=f.get("25"),
            pays=f.get("26"),
            extras=extras,
        )
        obj.validate_required_fields()
        return obj

    def validate_required_fields(self) -> None:
        # Check O* for Ligne 1 OR (Qualité, Prénom, Nom)
        has_ligne1 = bool(self.ligne1)
        has_full_identity = bool(self.qualite and self.prenom and self.nom)

        if not (has_ligne1 or has_full_identity):
            raise ValueError(
                "L'identité du bénéficiaire est obligatoire (champ 10 ou champs 11+12+13)."
            )

        # Mandatory fields (O)
        # Note: In some examples, these can be empty but present.
        # The spec says O, but sometimes they are empty strings.
        # We check presence in the fields dictionary or if they are not None if we want strictness.
        # Given the reference doc28, we check if they are set.

        # In the example Page 225, 20 and 23 are <vide> (empty).
        # So we should allow them to be empty strings if they are present.

        if self.ligne2 is None:
            raise ValueError("Ligne 2 de l'adresse (20) est obligatoire.")
        if self.ligne3 is None:
            raise ValueError("Ligne 3 de l'adresse (21) est obligatoire.")
        if not self.voie:
            raise ValueError("Voie de l'adresse (22) est obligatoire.")
        if self.ligne5 is None:
            raise ValueError("Ligne 5 de l'adresse (23) est obligatoire.")
        if not self.code_postal:
            raise ValueError("Code postal (24) est obligatoire.")
        if not self.localite:
            raise ValueError("Localité (25) est obligatoire.")
        if not self.pays:
            raise ValueError("Pays (26) est obligatoire.")


@register("00", "justificatif_domicile")
def _handle_00(doc: Decoded2DDoc) -> JustificatifDomicile:
    return JustificatifDomicile.from_decoded(doc)
