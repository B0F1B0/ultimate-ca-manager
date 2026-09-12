"""Private-key material helpers shared by the exporters.

The exporters used to fall back to the value stored in the database when
decryption failed, which archives the at-rest ciphertext in the field that a
restore treats as a PEM: the backup succeeds, and the restored key is
unusable. Decryption failures abort the backup here instead.
"""
import base64

from .errors import BackupExportError

_PEM_MARKER = '-----BEGIN'


def decrypt_stored_key(stored, *, label: str) -> str:
    """Return the decrypted stored key material, never the stored ciphertext.

    `stored` is whatever the column holds: base64 of a PEM, a raw PEM from
    before at-rest encryption, optionally wrapped by the key-encryption layer.
    """
    if isinstance(stored, bytes):
        try:
            stored = stored.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise BackupExportError(
                f"The private key of {label} is not readable key material"
            ) from exc

    from security.encryption import decrypt_private_key
    try:
        return decrypt_private_key(stored)
    except Exception as exc:
        raise BackupExportError(
            f"The private key of {label} could not be decrypted "
            "(wrong or missing key-encryption key)"
        ) from exc


def _pem_of(value: str):
    """Return the PEM carried by `value`, either directly or base64-wrapped."""
    if not isinstance(value, str) or not value:
        return None
    if _PEM_MARKER in value:
        return value
    try:
        decoded = base64.b64decode(value, validate=True).decode('utf-8')
    except Exception:
        return None
    return decoded if _PEM_MARKER in decoded else None


def as_pem(value: str, *, label: str) -> str:
    """Return `value` as a PEM, or abort the backup."""
    pem = _pem_of(value)
    if pem is None:
        raise BackupExportError(
            f"The private key of {label} did not decrypt to a usable PEM"
        )
    return pem


def ensure_key_material(value: str, *, label: str) -> str:
    """Return `value` unchanged once it is known to carry a PEM.

    Used where the archive keeps the stored (base64) encoding: the check still
    rules out an at-rest ciphertext travelling as if it were the key.
    """
    if _pem_of(value) is None:
        raise BackupExportError(
            f"The private key of {label} did not decrypt to a usable PEM"
        )
    return value
