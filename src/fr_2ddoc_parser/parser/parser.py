from __future__ import annotations

import base64
import re
from datetime import date, timedelta
from typing import Dict, Optional

from fr_2ddoc_parser.exception.exceptions import (
    TwoDDocFormatError,
    TwoDDocUnsupportedVersion,
)
from fr_2ddoc_parser.model.models import GS, US, Header, Decoded2DDoc, SignatureBlock
from fr_2ddoc_parser.parser.spec import SPEC_2D

# Record Separator (truncation marker)
RS = "\x1e"

# Build indices
SPEC_INDEX: dict[str, tuple[int, int]] = {
    di.identifier.upper(): (di.min_size, di.max_size) for di in (SPEC_2D or [])
}
ID_RE = re.compile(r"^[0-9A-Z]{2}$")


# ---------------------------------------------------------------------------
# Normalisation des séparateurs (si la chaîne contient <GS>/<RS>/<US>, ␝/␞/␟
# ou des séquences littérales "\x1D"... parce qu'elle vient d'un log / doc).
def _normalize_separators(s: str) -> str:
    aliases = {
        "<GS>": GS,
        "␝": GS,
        "\\x1D": GS,
        "<US>": US,
        "␟": US,
        "\\x1F": US,
        "<RS>": RS,
        "␞": RS,
        "\\x1E": RS,
    }
    s = s.replace("\u00a0", " ")
    for k, v in aliases.items():
        s = s.replace(k, v)
    return s


# ---------------------------------------------------------------------------
# Base32 util (signature après US)
def _b32_fixpad(s: str) -> str:
    s = re.sub(r"\s+", "", s)
    pad = (-len(s)) % 8
    return s + ("=" * pad)


# ---------------------------------------------------------------------------
# Dates (jours hex depuis 2000-01-01) dans l’en-tête DC04
def _days_hex_to_date(hex_days: str) -> Optional[date]:
    if hex_days.upper() == "FFFF":
        return None
    try:
        days = int(hex_days, 16)
    except ValueError:
        return None
    return date(2000, 1, 1) + timedelta(days=days)


# ---------------------------------------------------------------------------
# En-tête (positions fixes selon version)
def parse_header(data: str) -> Header:
    if len(data) < 22 or not data.startswith("DC"):
        raise TwoDDocFormatError("Marqueur absent (doit commencer par 'DC').")

    ver_str = data[2:4]
    try:
        ver = int(ver_str)
    except ValueError:
        raise TwoDDocFormatError(f"Version invalide: {ver_str!r}")

    if ver not in (2, 3, 4):
        raise TwoDDocUnsupportedVersion(
            f"Version non supportée: {ver_str!r} (V02, V03 ou V04 uniquement)"
        )

    ca, cert = data[4:8], data[8:12]
    issue, sig = data[12:16], data[16:20]

    # Longueur d'en-tête selon version: V1/V2=22, V3=24, V4=26.
    if ver == 2:
        header_len = 22
        doc_type = data[20:22]
        perimeter = ""
        country = None
    elif ver == 3:
        if len(data) < 24:
            raise TwoDDocFormatError(
                "En-tête incomplet pour version 03 (24 caractères attendus)."
            )
        header_len = 24
        doc_type = data[20:22]
        perimeter = data[22:24]
        country = None
    else:  # ver == 4
        if len(data) < 26:
            raise TwoDDocFormatError(
                "En-tête incomplet pour version 04 (26 caractères attendus)."
            )
        header_len = 26
        doc_type = data[20:22]
        perimeter = data[22:24]
        country = data[24:26]

    return Header(
        raw=data[:header_len],
        marker="DC",
        version=ver,
        ca_id=ca,
        cert_id=cert,
        issue_date=_days_hex_to_date(issue),
        signature_date=_days_hex_to_date(sig),
        doc_type=doc_type,
        perimeter=perimeter,
        country=country,
        header_len=header_len,
    )


# ---------------------------------------------------------------------------
# Séparation payload / signature (US)
def split_payload_and_signature(s: str) -> tuple[str, Optional[str]]:
    if US in s:
        left, right = s.split(US, 1)
        sig = right.strip() or None
        return left, sig
    return s, None


# ---------------------------------------------------------------------------
# Lecture d’un champ fixe
def _read_fixed(payload: str, i: int, L: int) -> tuple[str, int]:
    j = min(i + L, len(payload))
    return payload[i:j], j


# Lecture d’un champ variable (bornes éventuelles)
def _read_variable(
    payload: str, i: int, min_len: int, max_len: int
) -> tuple[str, int, bool]:
    """
    Retourne (valeur, nouvelle_position, truncated)

    Règles implémentées:
    - Si on rencontre GS, on termine le champ et on consomme GS.
    - Si on rencontre RS, on termine le champ, on consomme RS et on marque truncated=True.
    - Si on rencontre US, on termine le champ (sans consommer US ici).
    - Si max_len >= 0 et on atteint la borne sup, on s’arrête sans GS (cas "pile à la borne").
      -> conforme à la doc : un champ variable peut enchaîner sans GS s'il atteint son max.
    - Si c’est le dernier champ: fin de payload suffit (pas de GS).
    """
    n = len(payload)
    j = i
    truncated = False
    limit = n if max_len < 0 else min(n, i + max_len)

    while j < limit:
        ch = payload[j]
        if ch == GS:
            val = payload[i:j]
            return val, j + 1, truncated
        if ch == RS:
            val = payload[i:j]
            return val, j + 1, True
        if ch == US:
            val = payload[i:j]
            return val, j, truncated
        j += 1

    # Atteint la limite (max) ou la fin de payload sans GS/RS/US
    val = payload[i:j]
    return val, j, truncated


# ---------------------------------------------------------------------------
# Parser champs générique basé sur SPEC_INDEX
def parse_fields(payload: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    i = 0
    n = len(payload)

    while i < n:
        # sauter GS résiduels s'il y en a
        if payload[i] == GS:
            i += 1
            continue
        # pas assez pour un ID
        if i + 2 > n:
            break

        fid = payload[i : i + 2]
        if not ID_RE.match(fid):
            # Données inattendues -> on essaie de rejoindre prochain GS ou la fin
            j_gs = payload.find(GS, i + 1)
            i = (j_gs + 1) if j_gs != -1 else n
            continue
        i += 2  # avance après l'ID

        min_len, max_len = SPEC_INDEX.get(fid, (0, -1))  # défaut: variable non bornée
        if min_len == max_len and min_len > 0:
            # longueur fixe
            val, i = _read_fixed(payload, i, min_len)
            out[fid] = val
            continue
        else:
            # longueur variable (bornée ou non)
            val, i_new, truncated = _read_variable(payload, i, min_len, max_len)
            # garde-fou minimal si la valeur est plus courte que min_len ET que
            # le flux n'a pas été arrêté par GS/RS/US (cas de chaînes mal formées)
            if len(val) < min_len and i_new < n and payload[i_new] not in (GS, RS, US):
                need = min_len - len(val)
                extra = payload[i_new : i_new + need]
                val += extra
                i_new += len(extra)
            out[fid] = val
            i = i_new
            continue

    return out


# ---------------------------------------------------------------------------
# Point d'entrée
def parse(data: str) -> Decoded2DDoc:
    if not isinstance(data, str):
        raise TwoDDocFormatError("'data' doit être une str (chaîne 2D-DOC lue).")

    data = _normalize_separators(data)

    header = parse_header(data)
    after_header = data[header.header_len :]

    payload_no_sig, sig_b32 = split_payload_and_signature(after_header)
    fields = parse_fields(payload_no_sig)

    sign_payload_bytes = (header.raw + payload_no_sig).encode("utf-8")

    sig_block = SignatureBlock(present=False)
    if sig_b32:
        try:
            sig_raw = base64.b32decode(_b32_fixpad(sig_b32), casefold=True)
        except Exception as e:
            raise TwoDDocFormatError(f"Signature Base32 invalide: {e}")
        sig_block = SignatureBlock(present=True, b32=sig_b32, raw=sig_raw)
        if len(sig_raw) == 64:
            sig_block.alg_hint = "P-256"
        elif len(sig_raw) == 96:
            sig_block.alg_hint = "P-384"
        elif len(sig_raw) == 132:
            sig_block.alg_hint = "P-521"

    return Decoded2DDoc(
        header=header,
        sign_payload=sign_payload_bytes,
        fields=fields,
        signature=sig_block,
    )
