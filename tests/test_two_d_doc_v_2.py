"""
Tests unitaires pour le décodage des 2D-DOC de type avis d'impôts (type 28).
"""

import pytest

from fr_2ddoc_parser.api import decode_2d_doc


class TestTwoDDocV2:
    """Tests old 2d doc v2."""

    @pytest.fixture
    def sample_2d_doc(self):
        """Fixture avec un 2D-DOC de quitance EDF anonymisé."""
        return "DC02FR03EDFD255E255E0001D2FD985688194158BAA118476D54422A<GS>10/MARTIN/JEAN<GS>20<GS>21<GS>221 RUE DE LA PAIX<GS>23<GS>2475000PARIS<GS>26FR<US>PSCKB5NJFQ766ZDFW324IRHEMUZWSVCUNOFOFPVRP7H4BCWSCKAQKOH3CYULBZIFR567SVLM2HB72ZQKQF76AUXVFVXGGP3DOPI6ZZQ"

    def test_decode_success(self, sample_2d_doc):
        """Test que le décodage réussit et retourne un résultat."""
        result = decode_2d_doc(sample_2d_doc)

        assert result is not None
        assert result.header is not None
        assert result.fields is not None
        assert result.signature is not None

        # V2: en-tête fixe à 22 caractères (pas de périmètre/pays).
        assert result.header.version == 2
        assert result.header.header_len == 22
        assert result.header.perimeter == ""

        # Le payload doit démarrer sur le champ "01" (et non être décalé).
        assert "01" in result.fields
        assert result.fields["01"] == "D2FD985688194158BAA118476D54422A"
