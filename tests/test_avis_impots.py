"""
Tests unitaires pour le décodage des 2D-DOC de type avis d'impôts (type 28).
"""

import pytest
from datetime import date
from decimal import Decimal

from fr_2ddoc_parser.api import decode_2d_doc
from fr_2ddoc_parser.type.doc28_avis_impots import AvisImposition, AdresseImposition
from fr_2ddoc_parser.exception.exceptions import TwoDDocFormatError


class TestAvisImpots:
    """Tests pour les avis d'impôts (document type 28)."""

    @pytest.fixture
    def sample_2d_doc(self):
        """Fixture avec un 2D-DOC d'avis d'impôts réel."""
        return "DC04FR000001FFFF23DC2801FR432,75<GS>44227801234567845202146RETI PATRICK<GS>4A310720224Y145 RUE JULLIARD/ZASPECIMEN/78320/LEVIS STNOM<GS>4163198<GS>47300112345678948RETISOPHIE<GS>4907019877654324V3542<GS>4W182<GS>4X3724<GS><US>6W76EBC3I2LWHBVGNNYTL34SC6V32S2GDCIQQZLZNMTKCHNVEUISJYUQH5WE3AJJICBNG3YMQ2NXXHP5ZHVOQE332R6TUJDHNOHQ6BI"

    def test_decode_success(self, sample_2d_doc):
        """Test que le décodage réussit et retourne un résultat."""
        result = decode_2d_doc(sample_2d_doc)

        assert result is not None
        assert result.header is not None
        assert result.fields is not None
        assert result.signature is not None

    def test_header_parsing(self, sample_2d_doc):
        """Test que l'en-tête est correctement parsé."""
        result = decode_2d_doc(sample_2d_doc)
        header = result.header

        assert header.marker == "DC"
        assert header.version == 4
        assert header.doc_type == "28"
        assert header.perimeter == "01"
        assert header.country == "FR"
        assert header.ca_id is not None
        assert header.cert_id is not None

    def test_signature_present(self, sample_2d_doc):
        """Test que la signature est présente et valide."""
        result = decode_2d_doc(sample_2d_doc)
        signature = result.signature

        assert signature.present is True
        assert signature.raw is not None
        assert len(signature.raw) > 0
        assert (
            signature.alg_hint is not None
        )  # Devrait détecter l'algo (P-256, P-384, etc.)

    def test_typed_data_is_avis_imposition(self, sample_2d_doc):
        """Test que les données typées sont bien un AvisImposition."""
        result = decode_2d_doc(sample_2d_doc)

        assert result.typed is not None
        assert isinstance(result.typed, AvisImposition)
        assert result.typed.doc_type == "28"

    def test_avis_impots_mandatory_fields(self, sample_2d_doc):
        """Test que tous les champs obligatoires sont présents."""
        result = decode_2d_doc(sample_2d_doc)
        avis = result.typed

        # Champs obligatoires
        assert avis.annee_revenue is not None

        assert avis.reference_avis is not None
        assert len(avis.reference_avis) > 0

        assert avis.nombre_parts is not None
        assert isinstance(avis.nombre_parts, Decimal)

        assert avis.declarant1 is not None
        assert "RETI PATRICK" in avis.declarant1

        assert avis.date_mise_en_recouvrement is not None
        assert isinstance(avis.date_mise_en_recouvrement, date)

    def test_avis_impots_optional_fields(self, sample_2d_doc):
        """Test les champs optionnels présents dans l'exemple."""
        result = decode_2d_doc(sample_2d_doc)
        avis = result.typed

        # Ces champs peuvent être None ou avoir une valeur
        assert avis.revenue_fiscal_de_reference is not None
        assert isinstance(avis.revenue_fiscal_de_reference, int)

        assert avis.impot_revenue_net is not None
        assert isinstance(avis.impot_revenue_net, int)

    def test_adresse_parsing(self, sample_2d_doc):
        """Test que l'adresse est correctement parsée."""
        result = decode_2d_doc(sample_2d_doc)
        avis = result.typed
        adresse = avis.adresse

        assert isinstance(adresse, AdresseImposition)
        assert adresse.full is not None

    def test_adresse_validation_ok(self, sample_2d_doc):
        """Test que l'adresse passe la validation."""
        result = decode_2d_doc(sample_2d_doc)
        avis = result.typed

        # La validation est appelée automatiquement dans from_decoded
        # Si on arrive ici sans exception, c'est que c'est ok
        assert avis.adresse.is_ok_28() is True

    def test_invalid_format_raises_error(self):
        """Test qu'un format invalide lève une erreur."""
        with pytest.raises(TwoDDocFormatError):
            decode_2d_doc("INVALID_2D_DOC")

    def test_wrong_version_raises_error(self):
        """Test qu'une version non supportée lève une erreur."""
        # DC05 n'existe pas (seulement DC04 est supporté)
        invalid = "DC05FR06FPE6FFFF24712801FR"
        with pytest.raises(Exception):  # TwoDDocUnsupportedVersion
            decode_2d_doc(invalid)

    def test_fields_extraction(self, sample_2d_doc):
        """Test que les champs bruts sont extraits correctement."""
        result = decode_2d_doc(sample_2d_doc)

        assert "43" in result.fields  # nombre_parts
        assert "44" in result.fields  # reference_avis
        assert "45" in result.fields  # annee_revenue
        assert "46" in result.fields  # declarant1
        assert "4A" in result.fields  # date_mise_en_recouvrement
        assert "4Y" in result.fields  # adresse

    def test_nombre_parts_format(self, sample_2d_doc):
        """Test que le nombre de parts est au format Decimal."""
        result = decode_2d_doc(sample_2d_doc)
        avis = result.typed

        assert isinstance(avis.nombre_parts, Decimal)
        assert avis.nombre_parts > 0

    def test_date_format(self, sample_2d_doc):
        """Test que les dates sont au bon format."""
        result = decode_2d_doc(sample_2d_doc)

        # Date dans l'en-tête
        if result.header.issue_date:
            assert isinstance(result.header.issue_date, date)

        # Date de mise en recouvrement
        avis = result.typed
        assert isinstance(avis.date_mise_en_recouvrement, date)
        assert avis.date_mise_en_recouvrement.year >= 2000


class TestAdresseImposition:
    """Tests spécifiques pour la classe AdresseImposition."""

    def test_adresse_complete_valid(self):
        """Test qu'une adresse avec 4Y est valide."""
        adresse = AdresseImposition(full="123 Rue de Paris, 75001 PARIS")
        assert adresse.is_ok_28() is True

    def test_adresse_structuree_valid(self):
        """Test qu'une adresse structurée complète est valide."""
        adresse = AdresseImposition(
            voie="123 Rue de Paris", code_postal="75001", commune="PARIS", pays="FRANCE"
        )
        assert adresse.is_ok_28() is True

    def test_adresse_incomplete_invalid(self):
        """Test qu'une adresse incomplète est invalide."""
        adresse = AdresseImposition(
            voie="123 Rue de Paris",
            code_postal="75001",
            # Manque commune et pays
        )
        assert adresse.is_ok_28() is False

    def test_adresse_empty_invalid(self):
        """Test qu'une adresse vide est invalide."""
        adresse = AdresseImposition()
        assert adresse.is_ok_28() is False
