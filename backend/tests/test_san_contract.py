"""The SAN corpus the browser is held to, checked against the decider.

`frontend/src/lib/sanValidate.js` exists so a mistyped SAN is caught before
the request leaves the page. That is a convenience, never a control: the
server refuses on its own. What it must not do is disagree, and it did --
the IP field accepted `999.999.999.999` and the server answered "use DNS
type", while the DNS field refused the same value with "use IP type". Each
type pointed at the other and the value could not be entered at all.

`contracts/san_contract.json` is the corpus both sides answer. This file
proves the backend's answers are the ones written there;
`frontend/src/lib/__tests__/sanContract.test.js` proves the browser gives
the same ones. Neither file is the contract -- the JSON is.
"""
import json
import os

import pytest

from utils.san_parse import (validate_dns_san, validate_email_san,
                             validate_ip_san, validate_upn_san,
                             validate_uri_san)

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONTRACT = os.path.join(_REPO, 'contracts', 'san_contract.json')

VALIDATORS = {
    'dns': validate_dns_san,
    'email': validate_email_san,
    'ip': validate_ip_san,
    'upn': validate_upn_san,
    'uri': validate_uri_san,
}


def _cases():
    with open(CONTRACT) as fh:
        doc = json.load(fh)
    for san_type, rows in doc['types'].items():
        for row in rows:
            yield pytest.param(san_type, row['value'], row['valid'],
                               id=f'{san_type}:{row["value"] or "<empty>"}')


class TestTheCorpusIsWhatTheServerAnswers:
    def test_the_file_is_there(self):
        assert os.path.exists(CONTRACT), (
            f'{CONTRACT} is the shared corpus; the browser test reads the '
            'same file and neither side means anything without it')

    def test_every_type_the_server_validates_is_covered(self):
        with open(CONTRACT) as fh:
            doc = json.load(fh)
        assert set(doc['types']) == set(VALIDATORS), (
            'a SAN type the server validates is missing from the corpus, so '
            'nothing checks the browser against it')

    def test_both_answers_appear_for_every_type(self):
        with open(CONTRACT) as fh:
            doc = json.load(fh)
        for san_type, rows in doc['types'].items():
            answers = {row['valid'] for row in rows}
            assert answers == {True, False}, (
                f'{san_type} only carries {answers}: a corpus that never '
                'refuses anything cannot catch a validator that accepts '
                'everything')

    @pytest.mark.parametrize('san_type,value,expected', list(_cases()))
    def test_the_server_answers_what_the_corpus_says(
            self, san_type, value, expected):
        error = VALIDATORS[san_type](value)
        assert (error is None) is expected, (
            f'{san_type} {value!r}: the corpus says '
            f'{"valid" if expected else "refused"} and the server said '
            f'{error!r}')
