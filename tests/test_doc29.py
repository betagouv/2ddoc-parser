from datetime import date
from decimal import Decimal

from fr_2ddoc_parser.api import decode_2d_doc
from fr_2ddoc_parser.type.doc29_attestation_activite_professionnelle import (
    AttestationActiviteProfessionnelle,
)


def test_decode_attestation_activite_professionnelle():
    """Test le décodage d'un 2D-DOC de type 29 (Attestation d'Activité Professionnelle)

    contient l'ensemble des champs obligatoires et facultatifs avec des données ficitives.
    """
    raw_msg = (
        "DC04FR06PND025ED25ED2901FR"
        "62TESTNOM<GS>"
        "60TESTPRENOM<GS>"
        "6901011995"
        "5V012025122025"
        "5501092025"
        "5000000000000000"
        "5XINGENIEUR LOGICIEL<GS>"
        "5MCOMPANY TEST<GS>"
        "5W01"
        "5Y012025122025"
        "5Z2500,00<GS>"
        "562518"
        "<US>6XUO5EFXROOI3ZKCNI3JLOQ4AO22U6UZFQIFSY5VLWQYJ3532I6S23X6D6W2HZWHHYVA6F33GBRZYWWDBR6J3GXG7AASXQECMFSFLPA"
    )

    decoded = decode_2d_doc(raw_msg)

    assert decoded.header.doc_type == "29"
    assert isinstance(decoded.typed, AttestationActiviteProfessionnelle)

    typed: AttestationActiviteProfessionnelle = decoded.typed

    # Identité & Bénéficiaire
    assert typed.nom_patronymique == "TESTNOM"
    assert typed.liste_prenoms == "TESTPRENOM"
    assert typed.date_naissance == date(1995, 1, 1)
    assert typed.nom_complet_beneficiaire == "TESTNOM TESTPRENOM"

    # Employeur & Poste
    assert typed.siret_employeur == "00000000000000"
    assert typed.denomination_sociale == "COMPANY TEST"
    assert typed.intitule_poste == "INGENIEUR LOGICIEL"
    assert typed.nature_contrat == "01"

    # Dates & Périodes
    assert typed.date_debut_contrat == date(2025, 9, 1)
    assert typed.date_fin_contrat == date(2025, 12, 31)
    assert typed.periode_declaration_contrat == "012025122025"
    assert typed.periode_remuneration == "012025122025"

    # Rémunération
    assert typed.montant_remuneration == Decimal("2500.00")
