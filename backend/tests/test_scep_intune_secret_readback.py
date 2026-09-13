"""The Intune client secret reads back whether or not it was stored encrypted.

`decrypt_value` answers None for anything that is not one of its own tokens,
and the `or ''` turned that into an empty string. Two values land in that
column without being encrypted: one written before at-rest encryption was
enabled, and one put back by a restore -- an archive carries secrets in the
clear on purpose, so they survive a change of database key. Both read back as
no secret at all, and the Intune enrolment stopped working without a word.
"""
import pytest

from models import db
from models.scep import ScepProfile
from utils.encryption import encrypt_value

SECRET = 'zz-intune-client-secret'


@pytest.fixture
def profile(app):
    """A SCEP profile of this test's own, removed afterwards."""
    with app.app_context():
        row = ScepProfile(name='zz-intune-readback',
                          url_slug='zz-intune-readback',
                          ca_refid='zz-intune-ca')
        db.session.add(row)
        db.session.commit()
        profile_id = row.id

    yield profile_id

    with app.app_context():
        ScepProfile.query.filter_by(name='zz-intune-readback').delete(
            synchronize_session=False)
        db.session.commit()


class TestTheSecretComesBack:
    def test_an_encrypted_secret_is_decrypted(self, app, profile):
        with app.app_context():
            row = db.session.get(ScepProfile, profile)
            row.intune_client_secret = encrypt_value(SECRET)
            db.session.commit()

            assert row.decrypted_intune_secret() == SECRET

    def test_a_secret_a_restore_put_back_in_the_clear_still_reads(
            self, app, profile):
        """What the restore writes: the archive carries it readable so that it
        survives an installation with another database key."""
        with app.app_context():
            row = db.session.get(ScepProfile, profile)
            row.intune_client_secret = SECRET
            db.session.commit()

            assert row.decrypted_intune_secret() == SECRET, \
                'the secret read back as nothing at all'

    def test_no_secret_is_still_no_secret(self, app, profile):
        with app.app_context():
            row = db.session.get(ScepProfile, profile)
            row.intune_client_secret = None
            db.session.commit()

            assert row.decrypted_intune_secret() == ''
