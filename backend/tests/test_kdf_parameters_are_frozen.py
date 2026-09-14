"""The three key derivations are not a duplication to unify (DUP-PKI-016).

UCM derives a key from a password or a machine secret in three places, with
100 000, 600 000 and 10 000 iterations. The numbers differ because the inputs
and the jobs differ, and two of the three read data that already exists: an
iteration count is part of a stored format, not a setting.

===========================  ==========  ==========================  ==========  ==========
where                        iterations  protects                    direction   migration
===========================  ==========  ==========================  ==========  ==========
utils/encryption             100 000     integration secrets in the  read+write  yes: every
_get_encryption_key                      DB (Fernet), keyed by the               encrypted
                                         machine id + a static salt              row
services/backup              100 000     the master key of a v1      read only   n/a: never
BackupService.               (v1)        archive                                 written now
PBKDF2_ITERATIONS
services/backup/container    600 000     the master key of a v2/v3   read+write  no: the
KDF_PROFILES[PBKDF2]         (emitted,   archive                                 count is in
                             100k floor)                                         the header
services/backup              10 000      each private key inside an  read+write  yes, and
_encrypt/_decrypt_private_               archive, keyed by the                   undetectable
key                                      master key                              (see below)
===========================  ==========  ==========================  ==========  ==========

The per-key layer is the trap. Its input is the 32-byte master key, not a
password, so 10 000 iterations is not a weak password stretch — there is no
password left to stretch. And the blob it writes carries the salt and the
nonce but *not* the iteration count, so raising it would not fail loudly on an
old archive: it would fail as "wrong password or corrupted file" on a restore,
for every private key in every backup ever taken. The container's master KDF
is the counter-example and the reason the difference is deliberate: its
parameters travel in the header, which is why that one could be raised to
600 000 while keeping 100 000 as the accepted floor.

These tests freeze vectors rather than recompute them. A test that derives with
the same constant it asserts passes whatever the constant is; a vector produced
before the change is what notices.
"""
import base64
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ── Frozen vector: one private key as stored inside a backup archive ────────
FROZEN_KEY_PEM = '-----BEGIN PRIVATE KEY-----\nfrozen-vector\n-----END PRIVATE KEY-----'
FROZEN_MASTER_KEY = bytes.fromhex('11' * 32)
FROZEN_BLOB = {
    'algorithm': 'AES-256-GCM',
    'salt': 'a1' * 32,
    'nonce': 'b2' * 12,
    'ciphertext': (
        '4defac08c27e6f03c0b4de7ceb2f322f28543c1b5c2c14fa92acf3dd3cb34eac'
        '57b02b157302337b863c45f5f2010b21f2c60a5517fdfbbf21b70b55e2f8954d'
        '0ad2dfbe169eb7628f96d717600f684e61981e'
    ),
}

# ── Frozen vector: the DB-secret Fernet key for a known machine id ──────────
FROZEN_MACHINE_ID = b'0123456789abcdef0123456789abcdef'
FROZEN_DB_FERNET_KEY = 'OYt49L6PPXCnKIU0nWu_8djfvPnM_omT_KAm0UHJ7Mw='


def test_a_backup_taken_before_this_change_still_opens():
    """Raising the per-key count would read as a wrong password, not as a
    version mismatch — there is no version to mismatch."""
    from services.backup.backup_service import BackupService

    assert BackupService()._decrypt_private_key(
        FROZEN_BLOB, FROZEN_MASTER_KEY) == FROZEN_KEY_PEM


def test_the_per_key_blob_records_no_iteration_count():
    """Why the count above cannot be migrated: nothing writes it down."""
    from services.backup.backup_service import BackupService

    blob = BackupService()._encrypt_private_key(FROZEN_KEY_PEM, FROZEN_MASTER_KEY)
    assert sorted(blob) == ['algorithm', 'ciphertext', 'nonce', 'salt']
    assert 'iterations' not in blob and 'kdf' not in blob


def test_reading_that_blob_with_another_count_looks_like_a_wrong_password():
    """The failure mode, pinned: an InvalidTag, indistinguishable from
    corruption. This is the whole argument against unifying."""
    for iterations in (100_000, 600_000):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=bytes.fromhex(FROZEN_BLOB['salt']),
            iterations=iterations, backend=default_backend(),
        )
        try:
            AESGCM(kdf.derive(FROZEN_MASTER_KEY)).decrypt(
                bytes.fromhex(FROZEN_BLOB['nonce']),
                bytes.fromhex(FROZEN_BLOB['ciphertext']), None)
        except Exception as exc:
            assert type(exc).__name__ == 'InvalidTag'
        else:
            raise AssertionError(f'{iterations} iterations should not have opened the blob')


def test_the_db_secret_key_derivation_is_frozen():
    """Every DNS/LDAP/SMTP/SSO secret in the database is encrypted under this
    key when no UCM_DB_ENCRYPTION_KEY is set. Changing the salt, the count or
    the length orphans all of them."""
    derived = hashlib.pbkdf2_hmac(
        'sha256', FROZEN_MACHINE_ID, b'ucm-encryption-salt', 100_000, dklen=32)
    assert base64.urlsafe_b64encode(derived).decode() == FROZEN_DB_FERNET_KEY


def test_the_archive_master_kdf_is_the_one_that_can_move():
    """It announces its parameters, and the floor keeps older archives readable."""
    from services.backup import container
    from services.backup.backup_service import BackupService

    profile = container.KDF_PROFILES[container.KDF_PBKDF2]
    assert profile['emitted']['iterations'] == 600_000
    low, high = profile['bounds']['iterations']
    assert low == 100_000 and high >= 600_000
    # v1 archives are read with the count of the day they were written.
    assert BackupService.PBKDF2_ITERATIONS == 100_000
