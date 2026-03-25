from datetime import date
from decimal import Decimal

from fr_2ddoc_parser.api import decode_2d_doc
from fr_2ddoc_parser.type.doc06_bulletin_salaire import BulletinSalaire


def test_decode_bulletin_salaire():
    # Message from Page_227 - Type_06 - Bulletin de salaire.md
    # IDs: 10, 50, 51, 52, 53, 54, 55, 58, 59
    raw_msg = "DC03FR00000112511636060110M/EXEMPLE/HENRY\x1d5000000000000000510157,55200934,553123154124F5515032012581319,24\x1d599894,3\x1d\x1fFCJYSMOD7KDZON5QGBKV355SCX2MDFOFU743UBYK2F3PR6D7EL6WRUUIRU5SQKYAY6OOO5NTPIDWJXSCV4X7VXBUHSUH2HVKY5GVXII"

    decoded = decode_2d_doc(raw_msg)

    assert decoded.header.doc_type == "06"
    assert isinstance(decoded.typed, BulletinSalaire)

    typed = decoded.typed
    assert typed.beneficiaire.ligne1 == "M/EXEMPLE/HENRY"
    assert typed.nom_beneficiaire == "M EXEMPLE HENRY"

    assert typed.siret_employeur == "00000000000000"

    # Dates
    # 53: 1231 -> 2012-10-01
    assert typed.debut_periode == date(2012, 10, 1)
    # 54: 124F -> 2012-10-31
    assert typed.fin_periode == date(2012, 10, 31)
    # 55: 15032012
    assert typed.debut_contrat == date(2012, 3, 15)

    # Amounts
    assert typed.salaire_net_imposable == Decimal("1319.24")
    assert typed.cumul_salaire_net_imposable == Decimal("9894.3")

    # Optional
    assert typed.nombre_heures_travaillees == Decimal("157.5")
    assert typed.cumul_heures_travaillees == Decimal("934.5")
