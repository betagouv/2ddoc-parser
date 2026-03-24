# Guide de Contribution 2ddoc-parser

Merci de l'intérêt que vous portez à l'amélioration de cette bibliothèque ! Ce guide vous aidera à ajouter de nouveaux types de documents 2D-DOC.

## 🛠 Workflow pour ajouter un type de document

### 1. Préparation
- Créez une nouvelle branche : `feat/add-doc[TYPE]-support`
- Identifiez le code type (ex: `42` pour le permis de conduire) et les spécifications correspondantes dans `/doc/spec_2d_doc/`.

### 2. Définir le modèle de données
Utilisez des modèles **Pydantic v2** (héritant de `BaseModel`) pour représenter la structure du document :

```python
from __future__ import annotations
from datetime import date
from typing import Optional, Dict, Literal
from pydantic import BaseModel, Field

class MonDocument(BaseModel):
    """Modèle typé pour [Description du document] (type XX)."""
    doc_type: Literal["XX"]

    # Champs obligatoires
    nom: str                    # ID_CHAMP (O)
    date_emission: date         # ID_CHAMP (O)

    # Champs facultatifs
    numero: Optional[str] = None # ID_CHAMP (F)

    # Champs supplémentaires non mappés
    extras: Dict[str, str] = Field(default_factory=dict)
```

### 3. Implémenter la logique de mapping
Ajoutez une méthode `@classmethod from_decoded(cls, d: Decoded2DDoc)` et enregistrez le handler :

```python
from fr_2ddoc_parser.registry.registry import register

@classmethod
def from_decoded(cls, d: Decoded2DDoc) -> "MonDocument":
    f = d.fields
    # Mapping ID -> Attributs
    # Utilisez les helpers : to_int, to_dec, to_date_ddmmyyyy
    return cls(
        doc_type=d.header.doc_type,
        nom=f.get("XX"),
        ...
    )

@register("XX", "nom_technique")
def _handle_xx(doc: Decoded2DDoc) -> MonDocument:
    return MonDocument.from_decoded(doc)
```

### 4. Tests unitaires
- Ajoutez un nouveau fichier dans `tests/test_docXX.py`.
- Utilisez un exemple réel (si disponible dans `/doc/examples_final/`).
- Vérifiez le parsing correct et la validation des champs obligatoires.

### 5. Documentation
- Ajoutez le nouveau type dans le tableau du `README.md`.

## 🧪 Lancer les tests

```bash
poetry run pytest tests/test_docXX.py
```

## 📜 Règles de codage
- **Typage strict** : Utilisez les annotations de type Python.
- **Pydantic v2** : Utilisez `BaseModel` et `Field`.
- **Nomenclature** : Utilisez des noms de variables explicites en français (proche de la spec ANTS).
