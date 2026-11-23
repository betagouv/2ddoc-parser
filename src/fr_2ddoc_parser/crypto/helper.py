from cryptography import x509
from cryptography.hazmat.primitives import hashes


def _scan_der_certs(data: bytes) -> list[x509.Certificate]:
    """
    Balaye le flux binaire et tente d'extraire des certificats DER en se basant
    sur l'en-tête ASN.1 SEQUENCE (0x30) + longueur (0x81/0x82 ou courte).
    Déduplique via fingerprint SHA-256.
    """
    out: list[x509.Certificate] = []
    seen: set[bytes] = set()

    i, n = 0, len(data)
    while i + 4 <= n:
        if data[i] != 0x30:  # SEQUENCE
            i += 1
            continue

        if i + 2 > n:
            break

        lb = data[i + 1]
        # Long form (2 octets)
        if lb == 0x82 and i + 4 <= n:
            L = (data[i + 2] << 8) | data[i + 3]
            total = 4 + L
        # Long form (1 octet)
        elif lb == 0x81 and i + 3 <= n:
            L = data[i + 2]
            total = 3 + L
        # Short form (< 0x80)
        elif lb < 0x80:
            L = lb
            total = 2 + L
        else:
            i += 1
            continue

        if total <= 0 or i + total > n:
            i += 1
            continue

        chunk = data[i : i + total]
        try:
            cert = x509.load_der_x509_certificate(chunk)
            fp = cert.fingerprint(hashes.SHA256())
            if fp not in seen:
                out.append(cert)
                seen.add(fp)
            i += total
            continue
        except Exception:  # noqa: BLE001
            # faux positif → on avance d’un octet et on réessaie
            i += 1
            continue

    return out
