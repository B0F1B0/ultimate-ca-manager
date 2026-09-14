"""One description of this API, and it is the one the server serves.

Two lived side by side. `backend/app.py` builds a Swagger 2.0 template that
flasgger serves at `/api/docs`, and its version is `config.APP_VERSION`, so
it cannot go stale. `docs/openapi.yaml` was an OpenAPI 3.1 document that
nothing served, nothing referenced from any code path, and nobody had
updated: it declared `version: 2.1.0` against a tree on 2.230, described 43
of some 370 routes, and seven of those 43 paths had no implementation at all
(`/cas/tree`, `/license`, `/crl/generate`, four WebAuthn paths whose real
routes live under `/auth/login/webauthn/`).

That is worse than having no machine-readable description, because it is the
file a client generator gets pointed at. What it generated was wrong in ways
the server then refuses: `role` without `auditor`, `key_algorithm:
ECDSA-P256` where the server wants `EC-P256`, a revocation-reason enum
missing `certificateHold` so a client could not place a certificate on hold,
and `validity_days: default: 365` for templates the API creates with 397.

The stale one is gone; `docs/API_REFERENCE.md` is the written reference and
`/api/docs` is the live one. This test is here so a third does not appear
and quietly freeze.
"""
import os
import re

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_DECLARES_A_SPEC = re.compile(
    r'^\s*(?:openapi|swagger)\s*:\s*["\']?\d', re.MULTILINE)

_SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'dist', 'build',
              '.pytest_cache', 'venv', '.venv', 'htmlcov', 'coverage_html'}


def _candidate_files():
    for base, dirs, names in os.walk(_REPO):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in names:
            if name.endswith(('.yaml', '.yml', '.json')):
                yield os.path.join(base, name)


class TestOnlyTheServedDescriptionExists:
    def test_the_stale_spec_is_gone(self):
        assert not os.path.exists(os.path.join(_REPO, 'docs', 'openapi.yaml')), (
            'docs/openapi.yaml is back. It was frozen at 2.1.0 while the '
            'product shipped 2.230, and a client generated from it called '
            'routes that do not exist')

    def test_no_unserved_api_description_is_checked_in(self):
        found = []
        for path in _candidate_files():
            try:
                with open(path, encoding='utf-8', errors='ignore') as fh:
                    head = fh.read(4096)
            except OSError:
                continue
            if _DECLARES_A_SPEC.search(head):
                found.append(os.path.relpath(path, _REPO))
        assert found == [], (
            'these files declare an API description that no route serves, so '
            f'nothing makes them track the code: {found}. The served one is '
            'built in backend/app.py and versioned from VERSION')

    def test_the_readme_does_not_advertise_it(self):
        with open(os.path.join(_REPO, 'README.md'), encoding='utf-8') as fh:
            readme = fh.read()
        assert 'openapi.yaml' not in readme, (
            'the README still points readers at a spec that is not there')


class TestTheServedDescriptionTracksTheProduct:
    def test_its_version_is_the_version_of_the_tree(self, client):
        with open(os.path.join(_REPO, 'VERSION'), encoding='utf-8') as fh:
            version = fh.read().strip()
        response = client.get('/api/docs/apispec.json')
        assert response.status_code == 200, response.data
        spec = response.get_json()
        assert spec['info']['version'] == version, (
            'the served description reports '
            f'{spec["info"]["version"]} for a tree on {version}')

    def test_it_describes_the_routes_that_exist(self, client):
        spec = client.get('/api/docs/apispec.json').get_json()
        paths = set(spec.get('paths') or {})
        # Not a coverage claim: just that it is generated from the running
        # rules rather than hand-written and left behind.
        assert paths, 'the served description lists no paths at all'
