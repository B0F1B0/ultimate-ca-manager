"""No module may quietly fall back to storing private keys in cleartext.

Twelve modules wrapped ``from security.encryption import encrypt_private_key``
in ``try/except ImportError`` and, on failure, defined::

    def encrypt_private_key(data):
        return data

That is not a degraded mode, it is a passthrough: the CA key, the certificate
key, the SSH CA key, the TSA signer key and every imported key would be
written to the database exactly as generated. Four more places did the same
with an inline ``except ImportError: pass`` around ``key_encryption``, leaving
the LDAP bind password and freshly generated CA/CSR keys in the clear.

Nothing in ``security/encryption.py`` — or anywhere else the ``security``
package pulls in — is an optional dependency, so the handler could never fire
in an installation where UCM starts at all. It was a loaded gun rather than a
live bug: one future optional import inside that package and every private-key
write turns into a plaintext write, with no error and no log line. The import
is now plain, so such a break stops the process instead.

The read side is different and was never dangerous: ``decrypt_private_key``
returning its input hands the caller ciphertext, which fails loudly the moment
anything tries to parse it as a key.
"""
from __future__ import annotations

import ast
import base64
import pathlib

import pytest

BACKEND = pathlib.Path(__file__).resolve().parent.parent

# Modules that had an identity fallback, plus the four inline ones.
GUARDED_MODULES = (
    'api/v2/cas/import_.py',
    'api/v2/cas/key.py',
    'api/v2/certificates/cert_create.py',
    'api/v2/certificates/cert_import.py',
    'api/v2/sso/helpers.py',
    'services/ca/ca_creation.py',
    'services/ca/ca_service.py',
    'services/cert/mixins/csr.py',
    'services/cert/mixins/import_export.py',
    'services/cert/mixins/lifecycle.py',
    'services/cert/renewal.py',
    'services/smart_import/importer.py',
    'services/ssh_ca_service.py',
    'services/tsa_signer_cert.py',
)

WRITE_SIDE = ('encrypt_private_key', 'encrypt_text', 'key_encryption')


def _import_error_handlers(tree):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        imported = set()
        for stmt in node.body:
            if isinstance(stmt, ast.ImportFrom) and stmt.module:
                if stmt.module.startswith('security.encryption'):
                    imported.update(a.name for a in stmt.names)
        if not imported:
            continue
        for handler in node.handlers:
            names = []
            if isinstance(handler.type, ast.Name):
                names = [handler.type.id]
            elif isinstance(handler.type, ast.Tuple):
                names = [e.id for e in handler.type.elts if isinstance(e, ast.Name)]
            if 'ImportError' in names or 'ModuleNotFoundError' in names:
                yield node, handler, imported


class TestNoSwallowedEncryptionImport:
    @pytest.mark.parametrize('relative', GUARDED_MODULES)
    def test_module_imports_encryption_plainly(self, relative):
        path = BACKEND / relative
        tree = ast.parse(path.read_text())
        swallowed = [
            sorted(imported)
            for _node, _handler, imported in _import_error_handlers(tree)
        ]
        assert not swallowed, (
            f'{relative} swallows an ImportError from security.encryption '
            f'for {swallowed}; a missing key-encryption module must stop the '
            'process, not silently store the key in cleartext')

    def test_no_backend_module_swallows_a_write_side_import(self):
        """Nothing anywhere may hide a failure on the encrypting side."""
        offenders = []
        for path in BACKEND.rglob('*.py'):
            if 'tests' in path.parts or '__pycache__' in path.parts:
                continue
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError:
                continue
            for _node, _handler, imported in _import_error_handlers(tree):
                if imported & set(WRITE_SIDE):
                    offenders.append(
                        f'{path.relative_to(BACKEND)}: {sorted(imported)}')
        assert not offenders, (
            'these hide an ImportError on the encrypting side, so the key or '
            f'secret would be written in cleartext: {offenders}')

    def test_no_module_defines_an_identity_encrypt(self):
        """The exact shape that made this a passthrough."""
        offenders = []
        for path in BACKEND.rglob('*.py'):
            if 'tests' in path.parts or '__pycache__' in path.parts:
                continue
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef):
                    continue
                if 'encrypt' not in node.name or not node.args.args:
                    continue
                body = [s for s in node.body
                        if not (isinstance(s, ast.Expr)
                                and isinstance(s.value, ast.Constant))]
                if (len(body) == 1 and isinstance(body[0], ast.Return)
                        and isinstance(body[0].value, ast.Name)
                        and body[0].value.id == node.args.args[0].arg):
                    offenders.append(
                        f'{path.relative_to(BACKEND)}:{node.lineno} {node.name}')
        assert not offenders, f'identity encrypt functions: {offenders}'


class TestTheRealFunctionStillEncrypts:
    """Guards the assertion the tests above rest on."""

    def test_encrypt_private_key_is_not_a_passthrough(self, app, encryption_enabled):
        from security.encryption import decrypt_private_key, encrypt_private_key

        plain = base64.b64encode(
            b'-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n').decode()
        stored = encrypt_private_key(plain)

        assert stored != plain, 'encrypt_private_key returned its input'
        assert base64.b64decode(stored).startswith(b'ENC:')
        assert b'BEGIN PRIVATE KEY' not in base64.b64decode(stored)
        assert decrypt_private_key(stored) == plain

    def test_the_modules_use_that_function(self):
        """Not a re-exported copy that could drift."""
        from security.encryption import encrypt_private_key

        import services.cert.renewal as renewal
        import services.ssh_ca_service as ssh_ca
        import services.tsa_signer_cert as tsa

        for module in (renewal, ssh_ca, tsa):
            assert module.encrypt_private_key is encrypt_private_key, (
                f'{module.__name__} no longer uses the real encrypt_private_key')
