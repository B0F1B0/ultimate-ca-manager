"""An archive written before a column existed implies the value its version
had, not today's default: deployment full chains carried the root before 089."""
from services.backup.restore.apply import legacy_defaults


def test_a_binding_without_the_column_keeps_its_root():
    assert legacy_defaults('deploy_bindings', {'fullchain_path': '/etc/ssl/fc.pem'}) == {'include_root': True}


def test_a_binding_that_names_the_column_is_left_alone():
    assert legacy_defaults('deploy_bindings', {'include_root': False}) == {}


def test_other_sections_have_nothing_implied():
    assert legacy_defaults('users', {}) == {}


def test_a_pre_089_binding_comes_back_with_its_root(app, auth_client, create_cert):
    """A real archive of this server, with the column forgotten as an older version would."""
    from models import db, DeployBinding
    from models.deploy import DeployTarget
    from security.encryption import encrypt_text
    from tests.test_backup_hostile_corpus import _forged, _restore
    cert = create_cert()
    with app.app_context():
        target = DeployTarget(name='legacy-target', host='legacy.example.test',
                              username='deploy', private_key=encrypt_text('k'))
        db.session.add(target)
        db.session.flush()
        db.session.add(DeployBinding(target_id=target.id, certificate_id=cert['id'],
                                     fullchain_path='/etc/ssl/fc.pem', include_root=False))
        db.session.commit()

        def forget_the_column(data):
            for row in data['deploy_bindings']:
                del row['include_root']
        blob = _forged(('certificate_authorities', 'certificates', 'deploy_targets', 'deploy_bindings'),
                       mutate=forget_the_column)
    assert _restore(auth_client, blob).status_code == 200
    with app.app_context():
        assert DeployBinding.query.filter_by(certificate_id=cert['id']).one().include_root is True


def test_a_pre_091_binding_inherits_its_archived_target_reload_command(
        app, auth_client, create_cert):
    """Migration 091 cannot touch binding rows inserted later by restore."""
    from models import db, DeployBinding
    from models.deploy import DeployTarget
    from security.encryption import encrypt_text
    from tests.test_backup_hostile_corpus import _forged, _restore
    cert = create_cert()
    with app.app_context():
        target = DeployTarget(
            name='legacy-reload-target', host='legacy-reload.example.test',
            username='deploy', private_key=encrypt_text('k'),
            reload_command='systemctl reload nginx')
        db.session.add(target)
        db.session.flush()
        db.session.add(DeployBinding(
            target_id=target.id, certificate_id=cert['id'],
            cert_path='/etc/ssl/cert.pem', reload_command=None))
        db.session.commit()

        def forget_binding_command(data):
            for row in data['deploy_bindings']:
                del row['reload_command']

        blob = _forged(
            ('certificate_authorities', 'certificates', 'deploy_targets',
             'deploy_bindings'), mutate=forget_binding_command)
    assert _restore(auth_client, blob).status_code == 200
    with app.app_context():
        restored = DeployBinding.query.filter_by(certificate_id=cert['id']).one()
        assert restored.reload_command == 'systemctl reload nginx'
