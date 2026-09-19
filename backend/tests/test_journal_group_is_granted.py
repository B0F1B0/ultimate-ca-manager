"""The service user can read the journal it is told to collect.

Both units log to the journal, and the diagnostic bundle collects it with
`journalctl -u ucm`. Reading a system unit's journal requires systemd-journal
membership, and the service user was only ever added to the SoftHSM group, so
`_collect_journal` returned nothing and the bundle shipped without the journal
its own description advertises.
"""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('recipe', ['packaging/debian/postinst', 'packaging/rpm/ucm.spec'])
def test_each_recipe_grants_journal_membership(recipe):
    body = (ROOT / recipe).read_text(encoding='utf-8')
    assert re.search(r'usermod\s+-aG\s+systemd-journal\b', body), \
        f'{recipe} does not add the service user to systemd-journal'


@pytest.mark.parametrize('recipe', ['packaging/debian/postinst', 'packaging/rpm/ucm.spec'])
def test_membership_is_skipped_when_the_group_is_absent(recipe):
    """A host without systemd-journal must not fail the install over it."""
    body = (ROOT / recipe).read_text(encoding='utf-8')
    assert re.search(r'getent\s+group\s+systemd-journal\b', body), \
        f'{recipe} does not check the group exists first'


@pytest.mark.parametrize('recipe', ['packaging/debian/postinst', 'packaging/rpm/ucm.spec'])
def test_a_failed_usermod_does_not_abort_the_install(recipe):
    body = (ROOT / recipe).read_text(encoding='utf-8')
    line = next(l for l in body.splitlines()
                if re.search(r'usermod\s+-aG\s+systemd-journal\b', l))
    assert '|| true' in line, f'{recipe} lets a failed usermod abort the install'


def test_the_units_still_log_to_the_journal():
    """The grant is pointless if the units stop writing there."""
    for unit in ('packaging/debian/ucm.service', 'packaging/rpm/ucm.service'):
        body = (ROOT / unit).read_text(encoding='utf-8')
        assert re.search(r'^StandardOutput=journal\s*$', body, re.M), f'{unit}'
        assert re.search(r'^StandardError=journal\s*$', body, re.M), f'{unit}'
