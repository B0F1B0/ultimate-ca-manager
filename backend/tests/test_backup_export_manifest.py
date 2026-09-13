"""What the manifest-driven export puts in an archive.

The export used to be twenty-seven hand-written dictionaries: a column added
to a model never reached an archive, and a secret encrypted with the source's
database key travelled as ciphertext nobody else could read. These tests pin
the two properties that fixes: everything is carried, and what is carried is
readable somewhere else.
"""
import base64
import json

import pytest

from models import db
from services.backup import manifest
from services.backup.export_generic import IdentityIndex, export_section

PASSWORD = 'Correct-Horse-Battery-9'


def _service():
    from services.backup_service import BackupService
    return BackupService()


@pytest.fixture(scope='module')
def payload(app):
    with app.app_context():
        svc = _service()
        blob = svc.create_backup(PASSWORD)
        _key, data = svc._decrypt_framed(blob, PASSWORD)
        return data


class TestSectionsNoArchiveUsedToCarry:
    @pytest.mark.parametrize('section', [
        'acme_client_accounts',   # upstream account key and EAB
        'ad_connector',
        'webhook_endpoints',
        'deploy_targets',
        'deploy_bindings',
        'scep_profiles',
        'ca_template_pins',
        'role_permissions',       # a custom role without them grants nothing
        'group_members',
        'webauthn_credentials',
    ])
    def test_the_section_is_present(self, payload, section):
        assert section in payload, f"{section} is still missing from the archive"


class TestFieldsNoArchiveUsedToCarry:
    def test_users_carry_their_authentication_state(self, payload):
        user = payload['users'][0]
        for field in ('totp_secret', 'totp_confirmed', 'totp_exempt', 'backup_codes',
                      'sso_provider_id', 'sso_external_id', 'custom_role_id',
                      'auth_source', 'preferences', 'force_password_change'):
            assert field in user, f"users.{field} is missing"

    def test_authorities_carry_their_recent_pki_settings(self, app, create_ca, payload):
        create_ca(cn='Manifest Fields CA')
        with app.app_context():
            rows = export_section('certificate_authorities', IdentityIndex())
        assert rows
        ca = rows[0]
        for field in ('url_slug', 'hsm_key_id', 'path_length', 'name_constraints_permitted',
                      'name_constraints_excluded', 'policy_constraints_require',
                      'policy_constraints_inhibit', 'inhibit_any_policy', 'sia_enabled',
                      'sia_urls', 'delta_crl_enabled', 'crl_publish_interval_hours',
                      'crl_digest', 'owner_group_id', 'created_by'):
            assert field in ca, f"certificate_authorities.{field} is missing"

    def test_certificates_carry_their_identifiers_and_renewal_history(
            self, app, create_ca, create_cert):
        ca = create_ca(cn='Manifest Cert Fields CA')
        issued = create_cert(cn='manifest-fields.example.com', ca_id=ca['id'])
        with app.app_context():
            rows = export_section('certificates', IdentityIndex())
        cert = next(r for r in rows if r['refid'] == issued['refid']) \
            if any('refid' in r for r in rows) else rows[0]
        for field in ('aki', 'ski', 'san_upn', 'renewed_at', 'renewed_times',
                      'template_overrides', 'subject_cn'):
            assert field in cert, f"certificates.{field} is missing"

    def test_smtp_carries_its_oauth2_credentials(self, app):
        from models.email_notification import SMTPConfig
        with app.app_context():
            created = False
            config = SMTPConfig.query.first()
            if config is None:
                config = SMTPConfig(smtp_host='smtp.example.test', smtp_port=587)
                db.session.add(config)
                db.session.commit()
                created = True
            try:
                rows = export_section('smtp_config', IdentityIndex())
            finally:
                if created:
                    db.session.delete(config)
                    db.session.commit()
        assert rows
        for field in ('smtp_auth_method', 'smtp_oauth_provider', 'smtp_oauth_client_id',
                      'smtp_oauth_client_secret', 'smtp_oauth_refresh_token',
                      'smtp_oauth_token_url', 'smtp_oauth_tenant_id'):
            assert field in rows[0], f"smtp_config.{field} is missing"


class TestRelationsTravelByIdentity:
    """A numeric id means nothing on the target; the identity beside it does."""

    def test_every_declared_reference_is_exported_with_its_identity(self, app):
        with app.app_context():
            index = IdentityIndex()
            for name, section in manifest.SECTIONS.items():
                if not section.references or section.optional:
                    continue
                rows = export_section(name, index)
                if not rows:
                    continue
                for column in section.references:
                    assert f'{column}_ref' in rows[0], \
                        f"{name}.{column} travels as a number only"

    def test_the_identity_is_the_target_row_not_its_primary_key(self, app, create_user):
        create_user(username='manifest_identity_user', role='operator')
        with app.app_context():
            from models import User
            from models.group import Group, GroupMember
            group = Group(name='manifest-identity-group')
            db.session.add(group)
            db.session.commit()
            user = User.query.filter_by(username='manifest_identity_user').first()
            db.session.add(GroupMember(group_id=group.id, user_id=user.id, role='member'))
            db.session.commit()
            try:
                rows = export_section('group_members', IdentityIndex())
                mine = [r for r in rows if r['group_id'] == group.id]
                assert mine, 'the membership was not exported'
                assert mine[0]['user_id_ref'] == {'username': 'manifest_identity_user'}
                assert mine[0]['group_id_ref'] == {'name': 'manifest-identity-group'}
            finally:
                GroupMember.query.filter_by(group_id=group.id).delete()
                db.session.delete(group)
                db.session.commit()


class TestSecretsLeaveWithTheArchive:
    """The gate of this lot: an archive must open on an installation that
    never had the source's database key."""

    def test_a_secret_is_carried_in_the_clear_inside_the_container(self, app, monkeypatch):
        from cryptography.fernet import Fernet
        from models.acme_models import DnsProvider
        import utils.encryption as enc

        with app.app_context():
            provider = DnsProvider(name='portable-dns', provider_type='cloudflare')
            provider.credentials = json.dumps({'api_token': 'portable-secret-token'})
            db.session.add(provider)
            db.session.commit()
            try:
                rows = export_section('dns_providers', IdentityIndex())
                mine = [r for r in rows if r['name'] == 'portable-dns'][0]
                assert 'portable-secret-token' in mine['credentials'], \
                    'the archive carries ciphertext instead of the credential'

                # The source's database key is gone: the archive must still
                # hold something usable, since it no longer depends on it.
                monkeypatch.setenv('UCM_DB_ENCRYPTION_KEY', Fernet.generate_key().decode())
                enc._cipher = None if hasattr(enc, '_cipher') else None
                assert 'portable-secret-token' in mine['credentials']
            finally:
                db.session.delete(provider)
                db.session.commit()

    def test_an_unreadable_secret_stops_the_backup(self, app, monkeypatch):
        from services.backup.errors import BackupExportError
        from models.acme_models import DnsProvider
        import utils.encryption as enc

        with app.app_context():
            provider = DnsProvider(name='unreadable-dns', provider_type='cloudflare')
            provider.credentials = json.dumps({'api_token': 'x'})
            db.session.add(provider)
            db.session.commit()
            stored = provider._credentials
            try:
                real = enc.decrypt_value
                monkeypatch.setattr(
                    enc, 'decrypt_value',
                    lambda value: None if value == stored else real(value))
                with pytest.raises(BackupExportError, match='could not be decrypted'):
                    export_section('dns_providers', IdentityIndex())
            finally:
                db.session.delete(provider)
                db.session.commit()


class TestKeyAndCertificateAreCheckedAtExport:
    """A mismatched pair is a fact of the source, recorded rather than
    refused: a backup must stay possible precisely when something is wrong,
    and the restore is where the pair is turned away."""

    def test_a_mismatch_is_recorded_in_the_archive(self, app, create_ca, monkeypatch):
        """Only a pair that could be compared and did not match is recorded:
        a record whose certificate or key cannot be read has not been shown to
        be anyone else's."""
        authority = create_ca(cn='Recorded Mismatch CA')
        with app.app_context():
            import utils.cert_issuer as issuer
            monkeypatch.setattr(issuer, 'private_key_matches', lambda key, cert: False)

            svc = _service()
            mine = next(row for row in svc._export_cas(True)
                        if row['refid'] == authority['refid'])
            assert mine.get('_key_mismatch'), 'the mismatch was not recorded on the row'

            blob = svc.create_backup(PASSWORD)
            _key, data = svc._decrypt_framed(blob, PASSWORD)
            recorded = data['metadata']['key_mismatches']
            assert f"certificate_authorities:{authority['refid']}" in recorded

    def test_a_matching_pair_records_nothing(self, app, create_ca):
        authority = create_ca(cn='Matching Pair CA')
        with app.app_context():
            svc = _service()
            blob = svc.create_backup(PASSWORD)
            _key, data = svc._decrypt_framed(blob, PASSWORD)
            assert f"certificate_authorities:{authority['refid']}" not in \
                data['metadata']['key_mismatches']


class TestSectionAccounting:
    def test_counts_and_digests_cover_every_section(self, payload):
        metadata = payload['metadata']
        sections = set(metadata['sections'])
        digests = set(metadata['section_digests'])
        carried = {k for k in payload if k not in ('metadata', 'checksum')}
        assert carried == sections, f"counts miss {sorted(carried - sections)}"
        assert carried == digests, f"digests miss {sorted(carried - digests)}"

    def test_a_modified_section_is_named(self, app, payload):
        from services.backup.errors import BackupSchemaError
        altered = json.loads(json.dumps(payload))
        altered['groups'].append({'name': 'ghost-group'})
        altered['metadata']['sections']['groups'] += 1   # hide it from the count
        with app.app_context():
            with pytest.raises(BackupSchemaError, match="section 'groups'"):
                _service()._check_payload_schema(altered)


class TestTheRestoreSaysWhatItLeavesBehind:
    """The export is ahead of the restore: what is carried but not applied is
    named, instead of passing for a complete restore."""

    def test_a_carried_but_unapplied_section_is_reported(self, app):
        from services.webhook_service import WebhookEndpoint
        with app.app_context():
            endpoint = WebhookEndpoint(name='manifest-report-hook',
                                       url='https://hook.example.test/x',
                                       events='["certificate.issued"]')
            db.session.add(endpoint)
            db.session.commit()
            try:
                svc = _service()
                blob = svc.create_backup(PASSWORD)
                results = svc.restore_backup(blob, PASSWORD)
                assert 'webhook_endpoints' in results['sections_not_restored']
            finally:
                db.session.delete(endpoint)
                db.session.commit()

    def test_the_route_says_it_too(self, app, auth_client):
        import io
        from services.webhook_service import WebhookEndpoint
        with app.app_context():
            endpoint = WebhookEndpoint(name='manifest-route-hook',
                                       url='https://hook.example.test/y',
                                       events='["certificate.issued"]')
            db.session.add(endpoint)
            db.session.commit()
            blob = _service().create_backup(PASSWORD)

        try:
            response = auth_client.post(
                '/api/v2/system/restore',
                data={'password': PASSWORD, 'file': (io.BytesIO(blob), 'a.ucmbkp')},
                content_type='multipart/form-data')
            assert response.status_code == 200, response.data
            message = json.loads(response.data)['message']
            assert 'does not restore' in message and 'webhook_endpoints' in message
        finally:
            with app.app_context():
                WebhookEndpoint.query.filter_by(name='manifest-route-hook').delete()
                db.session.commit()
