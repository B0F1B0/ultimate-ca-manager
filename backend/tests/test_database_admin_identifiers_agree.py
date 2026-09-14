"""The three copies of the identifier rule say the same thing.

`preflight`, `migration` and `verify` each spell out their own
`_SAFE_IDENT_RE` and `_safe_ident`, and the comments say why: each module
raises its own exception type and is read on its own, so a shared import would
buy one line and cost the reader the rule. That is a deliberate copy, kept.

What a deliberate copy needs is a guard against drift, which is this. It also
pins `_display`, which two of the three had: names come from an
operator-supplied database and can carry control characters or kilobytes of
padding, and `migration` was putting the raw value in its message.
"""
import pytest

from services.database_admin import migration, preflight, verify

MODULES = (preflight, migration, verify)

HOSTILE = [
    'users', '_x', 'A1', 'tab"le', "drop\x00", 'a' * 200, '1abc', '', 'sé',
    'x; DROP TABLE users', 'col\nname', 'ok_name',
]


class TestTheRuleIsTheSameInAllThree:
    def test_the_patterns_are_identical(self):
        patterns = {m.__name__: m._SAFE_IDENT_RE.pattern for m in MODULES}
        assert len(set(patterns.values())) == 1, (
            f'the deliberate copies have drifted: {patterns}')

    @pytest.mark.parametrize('name', HOSTILE)
    def test_they_accept_and_refuse_the_same_names(self, name):
        verdicts = []
        for module in MODULES:
            try:
                module._safe_ident(name)
                verdicts.append('accepted')
            except Exception:
                verdicts.append('refused')
        assert len(set(verdicts)) == 1, (
            f'{name!r}: {dict(zip([m.__name__ for m in MODULES], verdicts))}')


class TestNoneOfThemRepeatsARawName:
    @pytest.mark.parametrize('module', MODULES, ids=lambda m: m.__name__)
    def test_the_module_renders_the_name_before_reporting_it(self, module):
        assert hasattr(module, '_display'), (
            f'{module.__name__} reports identifiers without rendering them')

    @pytest.mark.parametrize('name', ['tab"le\x07', 'a' * 200, 'back\\slash'])
    def test_the_three_render_it_the_same(self, name):
        rendered = {m.__name__: m._display(name) for m in MODULES}
        assert len(set(rendered.values())) == 1, rendered

    def test_a_hostile_name_does_not_reach_the_message(self):
        """The point of rendering: control characters and quotes stay out."""
        for module in MODULES:
            with pytest.raises(Exception) as raised:
                module._safe_ident('tab"le\x07' + 'x' * 300)
            text = str(raised.value)
            assert '\x07' not in text, f'{module.__name__} passed a bell through'
            assert len(text) < 200, f'{module.__name__} passed 300 characters through'
