# Skill: add-2ddoc-type

Ce skill permet d'automatiser l'intégration d'un nouveau type de document 2D-DOC dans la bibliothèque en se basant sur la documentation technique et les exemples extraits.

## 🛠 Workflow détaillé

### 1. Collecte des informations
- Demander à l'utilisateur le **Code 2D-DOC** (ex: "01") et le **Nom du document** (ex: "Facture").
- Si ces informations ne sont pas fournies, s'arrêter et les demander explicitement.
- Créer une nouvelle branche Git : `feat/add_[CODE]_[NOM]_support`.

### 2. Analyse de la Spécification
- Rechercher dans le dossier `doc/spec_2d_doc/` les fichiers Markdown contenant le tableau descriptif du code demandé.
- Extraire la liste des identifiants (IDs), leurs descriptions et leurs formats (longueur, type de données).
- Identifier les champs obligatoires et facultatifs.

### 3. Implémentation du Modèle (Type)
- Créer un nouveau fichier dans `src/fr_2ddoc_parser/type/doc[CODE]_[NOM].py`.
- **Référence d'implémentation :** Se baser sur `src/fr_2ddoc_parser/type/doc28_avis_impots.py`.
- Implémenter une classe Pydantic héritant de `BaseModel`.
- **Enregistrement Automatique :** Utiliser le décorateur `@register("[CODE]", "[NOM_SLUG]")` importé de `fr_2ddoc_parser.registry.registry`.
- Mapper chaque identifiant 2D-DOC à un nom d'attribut Python explicite et typé.
- Utiliser des `Field` Pydantic pour stocker l'ID original (ex: `ref: str = Field(..., alias="43")`).

### 4. Création du Test Unitaire
- Rechercher dans `doc/examples_final/` le fichier correspondant au code (ex: `Page_XXX_Type_[CODE]...`).
- Extraire le contenu du bloc "Message complet (Brut)".
- Créer un fichier de test dans `tests/test_doc[CODE].py`.
- Rédiger un test qui :
    1. Appelle `decode_2d_doc()` avec le message brut.
    2. Vérifie que le type détecté est correct.
    3. Vérifie que les champs métier sont correctement parsés et typés.
- **Note :** Si aucun exemple n'est trouvé ou s'il est incomplet, créer un test minimal avec une chaîne "dummy" et prévenir l'utilisateur avec un message clair.

### 5. Mise à jour de la documentation
- Mettre à jour le fichier `README.md` dans la section "Types implémentés" en ajoutant une nouvelle ligne pour le type de document fraîchement ajouté.

### 6. Validation et Commit
- Exécuter le test avec `poetry run pytest tests/test_doc[CODE].py`.
- Si le test passe, effectuer un commit de tous les changements sur la branche :
    - `git add .`
    - `git commit -m "feat: add support for 2D-DOC type [CODE] ([NOM])"`
- Si le test échoue, corriger les erreurs avant de commiter.

## 📜 Règles de codage
- Respecter le style existant (Pydantic v2, typage strict).
- Utiliser des noms de variables en français pour coller à la nomenclature de l'ANTS si nécessaire.
- **Ne jamais modifier manuellement le fichier `registry.py`**; l'utilisation du décorateur `@register` dans le nouveau modèle suffit à l'enregistrement automatique du type.
