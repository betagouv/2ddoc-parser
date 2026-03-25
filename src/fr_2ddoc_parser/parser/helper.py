# -----------------------------
# Helpers de conversion
from datetime import date, datetime, timedelta
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


def to_date_hex(hex_days: Optional[str]) -> Optional[date]:
    if not hex_days or hex_days.upper() == "FFFF":
        return None
    try:
        days = int(hex_days, 16)
    except ValueError:
        return None
    return date(2000, 1, 1) + timedelta(days=days)


def format_name(s: Optional[str]) -> Optional[str]:
    """Nettoie les slashes (/NOM/PRENOM) pour retourner 'NOM PRENOM'."""
    if not s:
        return s
    # On vire les slashes de début/fin
    cleaned = s.strip("/")
    # On remplace les slashes internes par des espaces
    return cleaned.replace("/", " ").strip()
