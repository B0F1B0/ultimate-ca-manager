"""The unauthenticated test client belongs to one test.

`client` is the fixture tests use to assert that a route answers 401. Shared
across a module or the session, one test signing in with it leaves every
later test holding an authenticated session: the route answers 200 with a
full payload, and which tests fail depends on the order pytest picked, so it
looked like flakiness under load.

`tests/test_sso.py` carried the proof and the workaround side by side. Its
own module-scoped copy was signed into by `test_password_login_response_structure`,
and a later test worked around it with
`fresh = client.application.test_client()` rather than fixing the fixture.
"""
import ast
import pathlib

import pytest

TESTS = pathlib.Path(__file__).parent
SHARED_SCOPES = {'module', 'session', 'package', 'class'}


def _fixture_scope(decorator):
    """The scope of a `@pytest.fixture(...)`, or None if not a fixture."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    name = getattr(target, 'attr', getattr(target, 'id', None))
    if name != 'fixture':
        return None
    if not isinstance(decorator, ast.Call):
        return 'function'
    for keyword in decorator.keywords:
        if keyword.arg == 'scope' and isinstance(keyword.value, ast.Constant):
            return keyword.value.value
    return 'function'


def _client_fixtures(path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != 'client':
            continue
        for decorator in node.decorator_list:
            scope = _fixture_scope(decorator)
            if scope:
                yield node.lineno, scope


@pytest.mark.parametrize(
    'path', sorted(TESTS.glob('test_*.py')), ids=lambda p: p.name)
def test_no_test_file_shares_an_unauthenticated_client(path):
    shared = [(line, scope) for line, scope in _client_fixtures(path)
              if scope in SHARED_SCOPES]
    assert not shared, (
        f'{path.name} defines a `client` fixture with scope {shared[0][1]!r} '
        f'at line {shared[0][0]}. One test signing in with it authenticates '
        'every later test in its scope; drop the local fixture and use the '
        'one from conftest.')


def test_the_shared_conftest_client_is_per_test():
    for line, scope in _client_fixtures(TESTS / 'conftest.py'):
        assert scope == 'function', (
            f'conftest `client` is {scope!r}-scoped at line {line}')


def test_nobody_works_around_it_by_building_their_own():
    """The workaround this fixture makes unnecessary.

    Building one from `auth_client` is a different thing and stays allowed:
    that is how a test signs in as somebody else.
    """
    here = pathlib.Path(__file__).name
    culprits = [path.name for path in TESTS.glob('test_*.py')
                if path.name != here
                and ' client.application.test_client()' in path.read_text()]
    assert not culprits, (
        f'{culprits} build a second client to escape a shared one; the '
        'fixture is per-test now.')
