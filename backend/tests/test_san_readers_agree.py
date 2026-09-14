"""One reader for SAN entries, one way to drop a wildcard label (DUP-PKI-013).

Two habits were spread across the codebase:

* ``domain.lstrip('*.')``, in eight places, next to two that spelled the same
  intent correctly. ``lstrip`` strips *characters*, so the two disagree on any
  value whose first characters are a run of ``*`` and ``.`` — and
  ``POST /api/v2/acme/domains/test`` passes the raw request body through it
  without a syntax check first.
* a four-branch DNS/IP/email/URI cascade over the SAN extension, in thirteen
  places, none of which decoded the otherName UPN — although the column that
  stores it exists and the signing path fills it.
"""
import json
import uuid
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from models import db, Certificate
from utils.datetime_utils import utc_now
from utils.san_parse import strip_wildcard
from utils.upn_san import build_upn_other_name

UPN = 'holder@corp.example'


@pytest.mark.parametrize('domain,expected', [
    ('*.example.com', 'example.com'),
    ('example.com', 'example.com'),
    ('*.*.example.com', '*.example.com'),   # lstrip('*.') answers 'example.com'
    ('.example.com', '.example.com'),       # lstrip('*.') answers 'example.com'
    ('*.*.corp.example.com', '*.corp.example.com'),
    ('', ''),
])
def test_only_the_leading_wildcard_label_is_dropped(domain, expected):
    assert strip_wildcard(domain) == expected


def test_every_wildcard_stripper_gives_the_same_answer():
    """The DNS-01 name a provider publishes and the one the self-check polls."""
    from services.acme.acme_proxy_service import AcmeProxyService
    from services.acme.dns_selfcheck import challenge_txt_name

    domain = '*.*.example.com'
    assert AcmeProxyService._strip_wildcard(domain) == strip_wildcard(domain)
    assert challenge_txt_name(domain, {}) == f'_acme-challenge.{strip_wildcard(domain)}'


def test_no_module_strips_the_wildcard_by_characters_again():
    """A character strip reads like a prefix strip; that is how it came back."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for path in root.rglob('*.py'):
        parts = path.parts
        if 'tests' in parts or '__pycache__' in parts:
            continue
        for lineno, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if ".lstrip('*.')" in line or '.lstrip("*.")' in line:
                offenders.append(f'{path.relative_to(root)}:{lineno}')
    assert offenders == [], (
        'use utils.san_parse.strip_wildcard instead: ' + ', '.join(offenders)
    )


def _self_signed_with_upn():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'upn-import.example.test')])
    now = utc_now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName('upn-import.example.test'),
            build_upn_other_name(UPN),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_an_imported_certificate_keeps_the_upn_it_carries(app):
    """The signing path recorded the UPN; the import path threw it away."""
    from services.cert_service import CertificateService
    from utils.upn_san import extract_upns_from_san_list

    pem = _self_signed_with_upn()
    parsed = x509.load_pem_x509_certificate(pem.encode())
    san_ext = parsed.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    # What the signing path (services/ca/ca_signing.py) records for this cert.
    assert extract_upns_from_san_list(list(san_ext.value)) == [UPN]

    with app.app_context():
        imported = CertificateService.import_certificate(
            descr=f'UPN import {uuid.uuid4().hex[:8]}',
            cert_pem=pem,
            username='probe',
        )
        cert_id = imported.id
        try:
            row = db.session.get(Certificate, cert_id)
            assert row.san_upn_list == [UPN]
            assert json.loads(row.san_dns) == ['upn-import.example.test']
        finally:
            db.session.delete(db.session.get(Certificate, cert_id))
            db.session.commit()
