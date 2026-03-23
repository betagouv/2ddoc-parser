# -----------------------------
# Helpers de conversion
from datetime import date, datetime
from decimal import Decimal
from typing import Optional


def to_int(s: Optional[str]) -> Optional[int]:
    if not s:
        return None
    t = s.replace(" ", "").replace("\u00a0", "").replace(".", "").replace(",", "")
    try:
        return int(t)
    except ValueError:
        return None


def to_dec(s: Optional[str]) -> Optional[Decimal]:
    if not s:
        return None
    try:
        return Decimal(s.replace(",", "."))
    except Exception:
        return None


def to_date_ddmmyyyy(s: Optional[str]) -> Optional[date]:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%d%m%Y").date()
    except ValueError:
        return None


def format_name(s: Optional[str]) -> Optional[str]:
    """Nettoie les slashes (/NOM/PRENOM) pour retourner 'NOM PRENOM'."""
    if not s:
        return s
    # On vire les slashes de début/fin
    cleaned = s.strip("/")
    # On remplace les slashes internes par des espaces
    return cleaned.replace("/", " ").strip()
