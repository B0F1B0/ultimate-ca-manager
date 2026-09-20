"""An archive written before a column existed implies the value its version
had, not today's default: deployment full chains carried the root before 089."""
from services.backup.restore.apply import legacy_defaults


def test_a_binding_without_the_column_keeps_its_root():
    assert legacy_defaults('deploy_bindings', {'fullchain_path': '/etc/ssl/fc.pem'}) == {'include_root': True}


def test_a_binding_that_names_the_column_is_left_alone():
    assert legacy_defaults('deploy_bindings', {'include_root': False}) == {}


def test_other_sections_have_nothing_implied():
    assert legacy_defaults('users', {}) == {}
