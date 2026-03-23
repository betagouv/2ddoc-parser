from __future__ import annotations

from datetime import date
from typing import Dict, Optional, Union, Any

from pydantic import BaseModel, ConfigDict, Field

from fr_2ddoc_parser.crypto.crypto import verify_signature
from fr_2ddoc_parser.crypto.key_resolver import KeyResolver
from fr_2ddoc_parser.type.base import GenericDoc

GS = "\x1d"  # Group Separator (sépare les paires champ/valeur)
US = "\x1f"  # Unit Separator (sépare les données de la signature)


class Header(BaseModel):
    model_config = ConfigDict(frozen=True)

    raw: str
    marker: str
    version: int
    ca_id: str
    cert_id: str
    issue_date: Optional[date]
    signature_date: Optional[date]
    doc_type: str
    perimeter: str
    country: Optional[str] = None
    header_len: int = 0


class SignatureBlock(BaseModel):
    present: bool
    b32: Optional[str] = None
    raw: Optional[bytes] = None  # décodée en bytes
    alg_hint: Optional[str] = None  # "P-256"/"P-384"/"P-521" if detectable

    def __init__(
        self,
        present: bool = False,
        b32: Optional[str] = None,
        raw: Optional[bytes] = None,
        alg_hint: Optional[str] = None,
        **kwargs: Any,
    ):
        super().__init__(present=present, b32=b32, raw=raw, alg_hint=alg_hint, **kwargs)


class Decoded2DDoc(BaseModel):
    header: Header
    # Données brutes "avant US" (sert au hash/verify)
    sign_payload: bytes
    # Paires ID -> valeur (après parsing des segments GS)
    fields: Dict[str, str] = Field(default_factory=dict)
    # Variante typée (si un modèle dédié existe pour ce type)
    typed: Optional[Union[BaseModel, GenericDoc]] = None
    signature: SignatureBlock = Field(
        default_factory=lambda: SignatureBlock(present=False)
    )
    is_valid: bool = False
    ants_type: Optional[str] = None

    def __init__(
        self,
        header: Optional[Header] = None,
        sign_payload: bytes = b"",
        fields: Optional[Dict[str, str]] = None,
        typed: Optional[Union[BaseModel, GenericDoc]] = None,
        signature: Optional[SignatureBlock] = None,
        is_valid: bool = False,
        ants_type: Optional[str] = None,
        **kwargs: Any,
    ):
        if fields is None:
            fields = {}
        if signature is None:
            signature = SignatureBlock(present=False)
        # Handle positional args if header is passed
        super().__init__(
            header=header,
            sign_payload=sign_payload,
            fields=fields,
            typed=typed,
            signature=signature,
            is_valid=is_valid,
            ants_type=ants_type,
            **kwargs,
        )

    def verify(self, key_resolver: "KeyResolver"):
        """Vérifie la signature si présente via un résolveur de clé (AC+cert)."""
        if not self.signature.present or not self.signature.raw:
            raise ValueError("Pas de signature présente dans ce 2D-DOC.")
        pub = key_resolver.resolve(self.header.ca_id, self.header.cert_id)
        self.is_valid = verify_signature(self.sign_payload, self.signature.raw, pub)
