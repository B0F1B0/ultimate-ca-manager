"""
pytest configuration and fixtures for UCM backend tests.

Shared fixtures used by all test_*.py files:
  - app: Flask app with temp SQLite DB
  - client: unauthenticated test client
  - auth_client: authenticated as admin
  - viewer_client: authenticated as viewer (read-only)
  - create_ca: factory to create a root CA
  - create_cert: factory to create a certificate under a CA
  - create_user: factory to create a user
"""
import atexit
import pytest
import os
import shutil
import sys
import json
import tempfile

# Set required env vars at MODULE LOAD time, before any test file is collected.
# settings.py reads SECRET_KEY / JWT_SECRET_KEY at class-body load time, so they
# must be present before the first `from app import create_app` (which can be
# triggered by any test module's import or fixture).
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-testing')
os.environ.setdefault('JWT_SECRET_KEY', 'test-jwt-secret-key-for-testing')
os.environ.setdefault('UCM_ENV', 'test')
os.environ.setdefault('HTTP_REDIRECT', 'false')
os.environ.setdefault('INITIAL_ADMIN_PASSWORD', 'changeme123')
os.environ.setdefault('CSRF_DISABLED', 'true')

# Isolate DATA_DIR from the machine's live install. settings.py runs
# load_dotenv("/etc/ucm/ucm.env"), which on a dev box points DATA_DIR at the
# running service's data dir — tests would then write session files there
# (root-owned, breaking the service's session pruning) and touch its
# .restart_requested watcher signal. load_dotenv never overrides pre-set env
# vars, so pinning a temp dir here keeps tests off the real data dir.
if 'DATA_DIR' not in os.environ:
    _tmp_data_dir = tempfile.mkdtemp(prefix='ucm-test-data-')
    os.environ['DATA_DIR'] = _tmp_data_dir
    atexit.register(shutil.rmtree, _tmp_data_dir, ignore_errors=True)
os.environ.setdefault('UCM_DEV_MODE', 'true')

# Add backend to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _GuardResolverProxy:
    """Stand-in for utils.ssrf_protection's `socket` module (and ONLY its):
    getaddrinfo falls back to a fixed TEST-NET-3 answer when the real
    resolver fails; everything else forwards to the real socket module."""

    def __init__(self, real_socket):
        self._real = real_socket

    def __getattr__(self, name):
        return getattr(self._real, name)

    def getaddrinfo(self, host, *args, **kwargs):
        try:
            return self._real.getaddrinfo(host, *args, **kwargs)
        except self._real.gaierror:
            return [(self._real.AF_INET, self._real.SOCK_STREAM, 6, '',
                     ('203.0.113.10', 0))]


@pytest.fixture(autouse=True)
def _deterministic_dns(monkeypatch):
    """Make the SSRF guards' hostname resolution deterministic.

    The guards fail CLOSED on an unresolvable host (#256), which made every
    test that validates a made-up hostname (hook.example.com, fake OIDC
    issuers, ACME upstream stubs, ...) hostage to the runner's resolver: an
    honest resolver NXDOMAINs those names and the guard refuses them, while
    an NXDOMAIN-hijacking one resolves them and the guard does not. Neither
    outcome is about the code under test.

    Only utils.ssrf_protection's view of `socket` is replaced: real answers
    win, and only a resolver failure falls back to a fixed TEST-NET-3
    address, which the guards treat as public — so save-time URL validation
    passes deterministically. Everything else (requests, ldap3, discovery)
    keeps the REAL resolver, so an actual connection attempt to a made-up
    host still fails fast with the same error as before, instead of hanging
    on an unroutable address. SSRF-focused tests that need a specific answer
    or a resolution FAILURE monkeypatch ssrf_protection.socket.getaddrinfo
    themselves; that lands on this proxy instance and fully replaces the
    fallback for the test's duration.
    """
    import socket as _socket
    import utils.ssrf_protection as _ssrf

    monkeypatch.setattr(_ssrf, 'socket', _GuardResolverProxy(_socket))


@pytest.fixture(autouse=True)
def _reset_acme_proxy_caches():
    """Drop the ACME proxy's process-level caches around every test.

    The upstream directory, finalize-URL, challenge->order and Replay-Nonce
    caches are module-level by design — they outlive a request, which also
    means they outlive a test. Two modules that stub the same upstream
    directory URL with different payloads would otherwise see each other's
    entries, and a pooled nonce would make _get_nonce() skip the HEAD request
    a later test asserts on. Cleared on both sides so run order cannot matter.
    """
    from services.acme.acme_proxy_service import reset_proxy_caches

    reset_proxy_caches()
    yield
    reset_proxy_caches()


def _drop_unreadable_key_material(app):
    """Forget key material that was written under a now-discarded key.

    The test database is shared by the whole session, so a CA or certificate
    written while `encryption_enabled` held an ephemeral key stays there after
    the key is gone — and its key material can no longer be read by anything.
    Since the backup service refuses to export a key it cannot decrypt, one
    such leftover row would fail every later backup test. A row without key
    material is a state the product supports (an offline or imported CA), so
    the column is cleared rather than the row deleted, which would take its
    certificates and approvals with it.
    """
    from models import db, CA, Certificate
    from security.encryption import decrypt_private_key

    with app.app_context():
        changed = False
        for model in (CA, Certificate):
            for row in model.query.filter(model.prv.isnot(None)).all():
                try:
                    decrypt_private_key(row.prv)
                except Exception:
                    row.prv = None
                    changed = True
        if changed:
            db.session.commit()


@pytest.fixture
def encryption_enabled(monkeypatch, tmp_path, app):
    """Enable private-key encryption with an isolated ephemeral key."""
    from cryptography.fernet import Fernet
    from security import encryption as enc_mod

    with monkeypatch.context() as patch:
        patch.setattr(enc_mod, 'MASTER_KEY_PATH', tmp_path / 'master.key')
        patch.setenv('KEY_ENCRYPTION_KEY', Fernet.generate_key().decode('ascii'))
        patch.delenv('KEY_ENCRYPTION_KEY_FILE', raising=False)
        enc_mod.key_encryption.reload()
        assert enc_mod.key_encryption.is_enabled
        yield enc_mod

    enc_mod.key_encryption.reload()
    _drop_unreadable_key_material(app)


@pytest.fixture(scope='session')
def app():
    """Create Flask app with test configuration (shared across all tests)."""
    os.environ['SECRET_KEY'] = 'test-secret-key-for-testing'
    os.environ['JWT_SECRET_KEY'] = 'test-jwt-secret-key-for-testing'
    os.environ['UCM_ENV'] = 'test'
    os.environ['HTTP_REDIRECT'] = 'false'
    os.environ['INITIAL_ADMIN_PASSWORD'] = 'changeme123'
    os.environ['CSRF_DISABLED'] = 'true'
    os.environ['UCM_DEV_MODE'] = 'true'

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        os.environ['UCM_DATABASE_PATH'] = f.name
        temp_db = f.name

    from app import create_app
    application = create_app('testing')
    application.config['TESTING'] = True
    application.config['WTF_CSRF_ENABLED'] = False
    # Deterministic FQDN so CA OCSP/CDP/AIA auto-URL generation does not depend
    # on the CI runner's `hostname -f` (which can lack a domain part and thus
    # resolve to None, flaking tests that patch `ocsp_enabled=True` without a
    # configured protocol_base_url).
    application.config['FQDN'] = 'ucm.test'

    yield application

    if os.path.exists(temp_db):
        os.unlink(temp_db)


@pytest.fixture(scope='session')
def client(app):
    """Unauthenticated Flask test client."""
    return app.test_client()


@pytest.fixture(scope='session')
def auth_client(app):
    """Authenticated Flask test client (admin role)."""
    c = app.test_client()
    r = c.post('/api/v2/auth/login',
               data=json.dumps({'username': 'admin', 'password': 'changeme123'}),
               content_type='application/json')
    assert r.status_code == 200, f'Admin login failed: {r.data}'
    return c


@pytest.fixture(scope='module')
def viewer_client(app):
    """Authenticated test client with viewer role (read-only)."""
    admin = app.test_client()
    r = admin.post('/api/v2/auth/login',
                   data=json.dumps({'username': 'admin', 'password': 'changeme123'}),
                   content_type='application/json')
    assert r.status_code == 200

    # Create viewer user
    r = admin.post('/api/v2/users',
                   data=json.dumps({
                       'username': 'viewer_test',
                       'password': 'ViewerPass123!',
                       'email': 'viewer@test.local',
                       'role': 'viewer'
                   }),
                   content_type='application/json')

    # Login as viewer
    vc = app.test_client()
    r = vc.post('/api/v2/auth/login',
                data=json.dumps({'username': 'viewer_test', 'password': 'ViewerPass123!'}),
                content_type='application/json')
    if r.status_code == 200:
        return vc
    # Fallback — if viewer creation failed (already exists), just return admin
    return admin


# ============================================================
# Factory fixtures
# ============================================================

@pytest.fixture(scope='session')
def create_ca(auth_client):
    """Factory fixture to create a root CA. Returns CA dict."""
    _counter = [0]

    def _create(cn=None, **kwargs):
        _counter[0] += 1
        data = {
            'type': 'root',
            'commonName': cn or f'Test CA {_counter[0]}',
            'organization': 'Test Org',
            'country': 'US',
            'state': 'CA',
            'locality': 'Test City',
            'keyType': 'RSA',
            'keySize': 2048,
            'validityYears': 10,
            'hashAlgorithm': 'sha256',
        }
        data.update(kwargs)
        r = auth_client.post('/api/v2/cas',
                             data=json.dumps(data),
                             content_type='application/json')
        assert r.status_code in (200, 201), f'Create CA failed ({r.status_code}): {r.data}'
        result = json.loads(r.data)
        return result.get('data', result)
    return _create


@pytest.fixture(scope='session')
def create_cert(auth_client, create_ca):
    """Factory fixture to create a certificate. Returns cert dict."""
    _ca_cache = {}
    _counter = [0]

    def _create(cn=None, ca_id=None, **kwargs):
        _counter[0] += 1
        if ca_id is None:
            if 'default' not in _ca_cache:
                ca = create_ca(cn='Default Test CA')
                _ca_cache['default'] = ca.get('id', ca.get('ca_id', 1))
            ca_id = _ca_cache['default']

        data = {
            'cn': cn or f'test-cert-{_counter[0]}.example.com',
            'ca_id': ca_id,
            'validity_days': 365,
        }
        data.update(kwargs)
        r = auth_client.post('/api/v2/certificates',
                             data=json.dumps(data),
                             content_type='application/json')
        assert r.status_code in (200, 201), f'Create cert failed ({r.status_code}): {r.data}'
        result = json.loads(r.data)
        return result.get('data', result)
    return _create


@pytest.fixture(scope='session')
def create_user(auth_client):
    """Factory fixture to create a user. Returns user dict."""
    _counter = [0]

    def _create(username=None, role='operator', **kwargs):
        _counter[0] += 1
        data = {
            'username': username or f'testuser{_counter[0]}',
            'password': 'TestPass123!',
            'email': f'testuser{_counter[0]}@test.local',
            'role': role,
        }
        data.update(kwargs)
        r = auth_client.post('/api/v2/users',
                             data=json.dumps(data),
                             content_type='application/json')
        # If the username already exists in the shared session DB (e.g. a
        # rerun or shard collision in CI), fetch and return it instead of
        # failing with 500. Tests treat the user as ephemeral context.
        if r.status_code in (409, 500):
            r2 = auth_client.get('/api/v2/users')
            if r2.status_code == 200:
                users = json.loads(r2.data).get('data', [])
                for u in users:
                    if u.get('username') == data['username']:
                        return u
        assert r.status_code in (200, 201), f'Create user failed ({r.status_code}): {r.data}'
        result = json.loads(r.data)
        return result.get('data', result)
    return _create


@pytest.fixture
def clear_acme_public_vhost_settings(app):
    """Clear acme_public_* SystemConfig before and after tests that set them."""
    from models import db, SystemConfig

    keys = ('acme_public_vhost', 'acme_public_port', 'acme_public_tls_cert_id')

    def _delete_keys():
        with app.app_context():
            SystemConfig.query.filter(
                SystemConfig.key.in_(keys)
            ).delete(synchronize_session=False)
            db.session.commit()

    _delete_keys()
    yield
    _delete_keys()


@pytest.fixture
def set_acme_public_config(app, clear_acme_public_vhost_settings):
    """Callable fixture: persist acme_public_vhost/port SystemConfig rows.

    Depends on clear_acme_public_vhost_settings so any value set here is
    removed after the test (shared session-scoped DB).
    """
    from models import db, SystemConfig

    def _set(vhost: str = '', port: str = '443'):
        with app.app_context():
            for key, value in (
                ('acme_public_vhost', vhost),
                ('acme_public_port', port),
            ):
                row = SystemConfig.query.filter_by(key=key).first()
                if not row:
                    row = SystemConfig(key=key)
                    db.session.add(row)
                row.value = value
            db.session.commit()

    return _set


# ============================================================
# Helpers
# ============================================================

def get_json(response):
    """Parse JSON response, return dict."""
    return json.loads(response.data)


def assert_success(response, status=200):
    """Assert response is successful and return parsed data."""
    assert response.status_code == status, \
        f'Expected {status}, got {response.status_code}: {response.data[:500]}'
    data = json.loads(response.data)
    return data.get('data', data)


def assert_error(response, status):
    """Assert response is an error with given status code."""
    assert response.status_code == status, \
        f'Expected {status}, got {response.status_code}: {response.data[:500]}'
