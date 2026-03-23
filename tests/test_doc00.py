"""
Tests unitaires pour le décodage des 2D-DOC de type justificatif de domicile (type 00).
"""

import pytest

from fr_2ddoc_parser.api import decode_2d_doc
from fr_2ddoc_parser.type.doc00_justificatif_domicile import JustificatifDomicile


class TestJustificatifDomicile:
    """Tests pour les justificatifs de domicile (document type 00)."""

    @pytest.fixture
    def sample_2d_doc_00(self):
        """Fixture avec un 2D-DOC de justificatif de domicile issu des exemples officiels (Page 225)."""
        # On reconstitue la chaîne sans les sauts de ligne de la doc
        return (
            "DC03FR000001123F16360001"  # Header V3
            "26FR"                      # Pays (ID 26)
            "2457000"                   # Code Postal (ID 24)
            "10MLLE/SAMPLE/ANGELA<GS>"  # Ligne 1 (ID 10)
            "20<GS>"                    # Ligne 2 (ID 20) - vide
            "21BAT 2 ETG 3<GS>"         # Ligne 3 (ID 21)
            "227 PLACE DES SPECIMENS<GS>" # Voie (ID 22)
            "23<GS>"                    # Ligne 5 (ID 23) - vide
            "25METZ<GS>"                # Localité (ID 25)
            "<US>3HJIYP3OAJ4LIZNQXCTZMNQPTT5C2XICTEF4UGJ3NDE2CWM7HJOEEK4ACIY4CZOO5ZOFG35APDZMZQFEAEBWRZTW4CBPG35JE2FJ4EY"
        )

    def test_decode_success(self, sample_2d_doc_00):
        """Test que le décodage réussit."""
        result = decode_2d_doc(sample_2d_doc_00)

        assert result is not None
        assert result.header.doc_type == "00"
        assert isinstance(result.typed, JustificatifDomicile)

    def test_fields_parsing(self, sample_2d_doc_00):
        """Test que les champs sont correctement extraits et mappés."""
        result = decode_2d_doc(sample_2d_doc_00)
        doc = result.typed
        assert isinstance(doc, JustificatifDomicile)

        # Bénéficiaire
        assert doc.ligne1 == "MLLE SAMPLE ANGELA"
        
        # Adresse
        assert doc.pays == "FR"
        assert doc.code_postal == "57000"
        assert doc.ligne2 == ""
        assert doc.ligne3 == "BAT 2 ETG 3"
        assert doc.voie == "7 PLACE DES SPECIMENS"
        assert doc.ligne5 == ""
        assert doc.localite == "METZ"

    def test_name_formatting(self):
        """Test spécifique pour le formatage des noms avec slashes."""
        from fr_2ddoc_parser.parser.helper import format_name
        assert format_name("/SERINE/KEVIN") == "SERINE KEVIN"
        assert format_name("MLLE/SAMPLE/ANGELA") == "MLLE SAMPLE ANGELA"
        assert format_name("/TEST/") == "TEST"
        assert format_name(None) is None

    def test_mandatory_fields_validation(self):
        """Test la validation des champs obligatoires."""
        # Manque ID 10 ou (11,12,13)
        with pytest.raises(ValueError, match="L'identité du bénéficiaire est obligatoire"):
            # On simule un Decoded2DDoc manuellement ou on passe par from_decoded avec un mock
            # Pour faire simple, on teste via JustificatifDomicile directement
            from fr_2ddoc_parser.model.models import Header, Decoded2DDoc, SignatureBlock
            h = Header("", "DC", 3, "FR00", "0001", None, None, "00", "01", "FR", 24)
            d = Decoded2DDoc(header=h, sign_payload=b"", fields={"22": "rue", "24": "75000", "25": "Paris", "26": "FR"}, signature=SignatureBlock(False))
            # Ici il manque 20, 21, 23 aussi
            JustificatifDomicile.from_decoded(d)

    def test_interchangeable_identity(self):
        """Test que l'identité via 11+12+13 fonctionne aussi."""
        from fr_2ddoc_parser.model.models import Header, Decoded2DDoc, SignatureBlock
        h = Header("", "DC", 3, "FR00", "0001", None, None, "00", "01", "FR", 24)
        f = {
            "11": "MME", "12": "Jane", "13": "Doe",
            "20": "", "21": "", "22": "1 rue de la Paix", "23": "", "24": "75000", "25": "Paris", "26": "FR"
        }
        d = Decoded2DDoc(header=h, sign_payload=b"", fields=f, signature=SignatureBlock(False))
        doc = JustificatifDomicile.from_decoded(d)
        assert doc.qualite == "MME"
        assert doc.prenom == "Jane"
        assert doc.nom == "Doe"
