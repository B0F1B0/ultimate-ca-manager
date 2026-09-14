"""What the two domain tables accept, judged by one rule with one option.

``acme_domains`` (DNS-provider issuance) and ``acme_local_domains`` (internal
server) each carried their own ``_is_valid_domain``. They differed twice: the
local table accepts a bare private TLD on purpose (#290), and the DNS table's
pattern ended in ``$``, which in Python also matches just before a trailing
newline -- so ``"example.com\\n"`` was a valid entry on one side and not on the
other. Only the first difference was meant.
"""

import pytest

from api.v2.acme_domains import _is_valid_domain as dns_table
from api.v2.acme_local_domains import _is_valid_domain as local_table
from services.acme import domain_match


@pytest.mark.parametrize('domain', [
    'example.com',
    'foo.example.com',
    '*.example.com',
    'my-domain.com',
    '123.com',
])
def test_both_tables_accept_ordinary_names(domain):
    assert dns_table(domain)
    assert local_table(domain)


@pytest.mark.parametrize('domain', [
    '',
    '   ',
    '*',
    '*.',
    '.com',
    'example.com.',
    '**.example.com',
    'exa_mple.com',
    'exa mple.com',
    '-example.com',
    'example-.com',
    '../etc/passwd',
    'ex\nample.com',
])
def test_both_tables_refuse_malformed_names(domain):
    assert not dns_table(domain)
    assert not local_table(domain)


@pytest.mark.parametrize('domain', ['local', 'internal', 'ab', '*.local'])
def test_only_the_local_table_takes_a_bare_tld(domain):
    """The one difference that is meant: #290, kept exactly as it was."""
    assert local_table(domain)
    assert not dns_table(domain)


@pytest.mark.parametrize('domain', [
    'example.com\n',
    '*.example.com\n',
    'local\n',
])
def test_neither_table_takes_a_trailing_newline(domain):
    """``$`` let the DNS table through here; ``\\Z`` is what both use now."""
    assert not dns_table(domain)
    assert not local_table(domain)


def test_single_label_is_the_only_axis_between_the_two():
    """Every other answer agrees, so the rule can only be stated once."""
    for domain in ['example.com', '*.example.com', 'a', 'example.123',
                   'example.com\n', 'ex ample.com', '*.foo.example.com']:
        assert dns_table(domain) == local_table(domain), domain


def test_both_tables_call_the_shared_rule():
    assert domain_match.is_valid_entry('local', allow_single_label=True)
    assert not domain_match.is_valid_entry('local', allow_single_label=False)
    assert not domain_match.is_valid_entry('example.com\n',
                                           allow_single_label=True)
    assert not domain_match.is_valid_entry(None, allow_single_label=True)
