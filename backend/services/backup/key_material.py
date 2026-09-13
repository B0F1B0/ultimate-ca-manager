"""Private-key material helpers shared by the exporters.

The exporters used to fall back to the value stored in the database when
decryption failed, which archives the at-rest ciphertext in the field that a
restore treats as a PEM: the backup succeeds, and the restored key is
unusable. Decryption failures abort the backup here instead.
"""
import base64

import logging

from .errors import BackupExportError

logger = logging.getLogger(__name__)

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


def decrypt_stored_secret(stored, *, label: str):
    """Return a DB-encrypted secret in the clear, or abort the backup.

    The model properties that read these columns answer None when the value
    does not decrypt, and hand back the ciphertext when the key is missing
    altogether. Either one exports as if it were the secret: the archive looks
    complete and the restored integration silently has no usable credential.
    """
    if not stored:
        return stored

    from utils.encryption import decrypt_value, is_encrypted
    if not is_encrypted(stored):
        return stored  # stored before at-rest encryption was enabled

    try:
        value = decrypt_value(stored)
    except Exception as exc:
        raise BackupExportError(
            f"The stored secret of {label} could not be decrypted "
            "(wrong or missing database encryption key)"
        ) from exc

    if not value:
        raise BackupExportError(
            f"The stored secret of {label} could not be decrypted "
            "(wrong or missing database encryption key)"
        )
    return value


def key_matches_certificate(pem_key: str, certificate_der_or_pem, *, label: str) -> bool:
    """Whether a stored key is the key of the certificate stored beside it.

    A mismatch is a fact of the source database, not of the archive: refusing
    to back up would leave an administrator unable to save the very state they
    need to repair, which is the opposite of what a backup is for. So it is
    recorded rather than refused: the archive carries the list in its
    metadata, the log names the records, and the restore repeats both in its
    result. It is not refused there either, for the same reason it was not
    refused here — the state an administrator needs to repair has to be
    restorable — but it is never silent, because the authority it produces
    signs answers nobody can verify.

    Returns True when nothing could be checked (no key, no certificate, or
    material that cannot be parsed): unreadable is not proof of a mismatch.
    """
    if not pem_key or not certificate_der_or_pem:
        return True

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from utils.cert_issuer import private_key_matches

    try:
        data = certificate_der_or_pem
        if isinstance(data, str):
            data = data.encode()
        certificate = (x509.load_pem_x509_certificate(data)
                       if b'-----BEGIN' in data else x509.load_der_x509_certificate(data))
        key = serialization.load_pem_private_key(pem_key.encode(), password=None)
    except Exception:
        return True

    if private_key_matches(key, certificate):
        return True

    logger.warning(
        "Backup: the private key of %s does not match its certificate; the "
        "archive records the mismatch and a restore will refuse the pair", label)
    return False
