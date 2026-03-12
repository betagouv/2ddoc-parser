from __future__ import annotations

from datetime import date
from typing import Dict, Literal, Optional, cast

from fr_2ddoc_parser.model.models import Decoded2DDoc
from fr_2ddoc_parser.parser.helper import to_date_ddmmyyyy
from fr_2ddoc_parser.registry.registry import register
from pydantic import BaseModel, Field


# -----------------------------
# Adresse — Spécifique Titres Identité (07)
class AdresseIdentite(BaseModel):
    """Adresse pour Titres d'Identité (doc 07).
    Basé sur le tableau des spécifications.
    Champs disponibles :
    - 6S : Ligne 2 (F)
    - 6T : Ligne 3 (F)
    - 6U : Ligne 4 - Voie (O) -> Obligatoire
    - 6V : Ligne 5 - Lieu-dit (F)
    - 6W : Code postal (O) -> Obligatoire
    - 6X : Commune (Impliqué par le CP, souvent O)
    - 6Y : Code pays (F)
    """

    ligne_2: Optional[str] = None  # 6S
    ligne_3: Optional[str] = None  # 6T
    voie: Optional[str] = None  # 6U
    lieu_dit: Optional[str] = None  # 6V
    code_postal: Optional[str] = None  # 6W
    commune: Optional[str] = None  # 6X
    pays: Optional[str] = None  # 6Y


# -----------------------------
# Carte Nationale d'Identité (doc 07)
class CarteIdentite(BaseModel):
    """Modèle typé pour Carte Nationale d'Identité (07)."""

    doc_type: Literal["07"]

    # Données Personnelles
    liste_prenoms: str  # 60
    prenom: Optional[str] = None  # 61
    nom_patronymique: Optional[str] = None  # 62
    nom_usage: Optional[str] = None  # 63
    type_piece_identite: str  # 65
    numero_document: str  # 66
    nationalite: str  # 67
    genre: str  # 68
    date_naissance: Optional[date] = None  # 69
    lieu_naissance: Optional[str] = None  # 6A
    pays_naissance: str  # 6C

    # Données Document
    mrz: Optional[str] = None  # 6F
    date_debut_validite: Optional[date] = None  # 6N
    date_fin_validite: Optional[date] = None  # 6O

    adresse: AdresseIdentite = Field(default_factory=AdresseIdentite)

    # Champs supplémentaires non cartographiés
    extras: Dict[str, str] = Field(default_factory=dict)

    # -------------------------
    # Construction depuis Decoded2DDoc
    @classmethod
    def from_decoded(cls, d: Decoded2DDoc) -> "CarteIdentite":
        f = d.fields
        adresse = AdresseIdentite(
            ligne_2=f.get("6S"),
            ligne_3=f.get("6T"),
            voie=f.get("6U"),
            lieu_dit=f.get("6V"),
            code_postal=f.get("6W"),
            commune=f.get("6X"),
            pays=f.get("6Y"),
        )

        known = {
            "60",
            "61",
            "62",
            "63",
            "65",
            "66",
            "67",
            "68",
            "69",
            "6A",
            "6C",
            "6F",
            "6N",
            "6O",
            "6S",
            "6T",
            "6U",
            "6V",
            "6W",
            "6X",
            "6Y",
        }

        extras = {k: v for k, v in f.items() if k not in known}

        obj = cls(
            doc_type=cast(Literal["07"], d.header.doc_type),
            liste_prenoms=f.get("60", "").strip(),
            prenom=f.get("61"),
            nom_patronymique=f.get("62") or "",
            nom_usage=f.get("63"),
            type_piece_identite=f.get("65", "").strip(),
            numero_document=f.get("66", "").strip(),
            nationalite=f.get("67", "").strip(),
            genre=f.get("68", "").strip(),
            date_naissance=to_date_ddmmyyyy(f.get("69")),
            lieu_naissance=f.get("6A"),
            pays_naissance=f.get("6C") or "",
            mrz=f.get("6F"),
            date_debut_validite=to_date_ddmmyyyy(f.get("6N")),
            date_fin_validite=to_date_ddmmyyyy(f.get("6O")),
            adresse=adresse,
            extras=extras,
        )

        obj.validate_required_fields()
        return obj

    # -------------------------
    # Validation des règles O / F
    def validate_required_fields(self) -> None:
        # 1. Validation Prénoms (60) - O
        if not self.liste_prenoms:
            raise ValueError("La liste des prénoms (60) est obligatoire.")

        # 2. Validation Nationalité (67) - O
        if not self.nationalite:
            raise ValueError("La nationalité (67) est obligatoire.")

        # 3. Validation Genre (68) - O
        if not self.genre:
            raise ValueError("Le genre (68) est obligatoire.")


# -----------------------------
# Handlers d’enregistrement
@register("07", "carte_identite")
def _handle_07(doc: Decoded2DDoc) -> CarteIdentite:
    return CarteIdentite.from_decoded(doc)
