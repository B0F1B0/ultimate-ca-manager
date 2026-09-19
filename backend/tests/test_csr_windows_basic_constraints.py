"""The Windows NDES client writes BasicConstraints CA:FALSE with a path length,
a shape cryptography refuses wholesale, which broke Windows enrollment at the
certificate build (#228)."""
import asn1crypto.csr
import asn1crypto.x509
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import AttributeOID, ExtensionOID, NameOID

from models import SystemConfig, db
from services.scep.scep_service import SCEPService
from tests.test_scep_rfc8894_operations import (
    PKI_STATUS_OID, _build_request, _client_identity, _decrypt_response,
    _load_ca_material, _response_attributes,
)
from utils.csr_extensions import csr_extensions

CHALLENGE = 'windows horse battery staple'


def _windows_shaped_csr(key, cn, challenge=None):
    """A CSR the way the NDES client writes it: SAN, and CA:FALSE with pathLen 0."""
    builder = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False))
    if challenge:
        builder = builder.add_attribute(AttributeOID.CHALLENGE_PASSWORD, challenge.encode())
    clean = builder.sign(key, hashes.SHA256())
    req = asn1crypto.csr.CertificationRequest.load(clean.public_bytes(serialization.Encoding.DER))
    info = req['certification_request_info']
    attrs = []
    for attr in info['attributes']:
        if attr['type'].native != 'extension_request':
            attrs.append(attr)
            continue
        exts = list(attr['values'][0])
        exts.append(asn1crypto.x509.Extension({
            'extn_id': 'basic_constraints', 'critical': True,
            'extn_value': asn1crypto.x509.BasicConstraints({'ca': False, 'path_len_constraint': 0}),
        }))
        attrs.append(asn1crypto.csr.CRIAttribute({'type': 'extension_request',
                                                  'values': [asn1crypto.x509.Extensions(exts)]}))
    info['attributes'] = asn1crypto.csr.CRIAttributes(attrs)
    req['signature'] = key.sign(info.dump(), padding.PKCS1v15(), hashes.SHA256())
    return x509.load_der_x509_csr(req.dump())


class TestCsrExtensionsHelper:
    def test_windows_basic_constraints_is_read_as_an_end_entity(self):
        key = rsa.generate_private_key(65537, 2048)
        csr = _windows_shaped_csr(key, 'win.example.test')
        with pytest.raises(ValueError):
            csr.extensions  # the shape cryptography refuses
        exts = csr_extensions(csr)
        bc = exts.get_extension_for_class(x509.BasicConstraints).value
        assert bc == x509.BasicConstraints(ca=False, path_length=None)
        san = exts.get_extension_for_class(x509.SubjectAlternativeName).value
        assert san.get_values_for_type(x509.DNSName) == ['win.example.test']

    def test_a_well_formed_csr_is_read_as_is(self):
        key = rsa.generate_private_key(65537, 2048)
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'plain')]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName('plain')]), critical=False)
               .sign(key, hashes.SHA256()))
        assert list(csr_extensions(csr)) == list(csr.extensions)


@pytest.fixture
def scep_ca(app, create_ca):
    ca_data = create_ca(cn='SCEP Windows CSR CA')
    with app.app_context():
        db.session.add(SystemConfig(key=f'scep_challenge_{ca_data["id"]}', value=CHALLENGE))
        db.session.commit()
    yield ca_data
    with app.app_context():
        row = SystemConfig.query.filter_by(key=f'scep_challenge_{ca_data["id"]}').first()
        if row:
            db.session.delete(row)
            db.session.commit()


def test_windows_shaped_request_is_issued(app, scep_ca):
    with app.app_context():
        ca, ca_cert, _ = _load_ca_material(scep_ca['id'])
        signer_cert, key = _client_identity('windows device')
        csr = _windows_shaped_csr(key, 'win-device.example.test', CHALLENGE)
        request = _build_request(ca_cert, signer_cert, key, 19,
                                 csr.public_bytes(serialization.Encoding.DER), b'windows-nonce-16')
        response, status = SCEPService(ca.refid, challenge_password=CHALLENGE,
                                       auto_approve=True).process_pkcs_req(request, '127.0.0.1')
        attrs = _response_attributes(response)
        assert status == 200 and attrs[PKI_STATUS_OID] == '0', attrs
        import asn1crypto.cms
        degenerate = asn1crypto.cms.ContentInfo.load(_decrypt_response(response, key, signer_cert))
        issued = x509.load_der_x509_certificate(degenerate['content']['certificates'][0].chosen.dump())
        assert issued.extensions.get_extension_for_class(x509.BasicConstraints).value == \
            x509.BasicConstraints(ca=False, path_length=None)
        assert issued.extensions.get_extension_for_class(x509.SubjectAlternativeName).value \
            .get_values_for_type(x509.DNSName) == ['win-device.example.test']
