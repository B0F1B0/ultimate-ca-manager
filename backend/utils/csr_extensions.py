"""Reading a CSR's extensions when its BasicConstraints is malformed the Windows way."""
import asn1crypto.core
import asn1crypto.csr
import asn1crypto.x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# PKCS#9 extensionRequest, and Microsoft's own attribute for the same set
_EXTENSION_ATTRIBUTES = ('extension_request', '1.3.6.1.4.1.311.2.1.14')


class _ExtensionSets(asn1crypto.core.SetOf):
    _child_spec = asn1crypto.x509.Extensions


def csr_extensions(csr: x509.CertificateSigningRequest) -> x509.Extensions:
    """The CSR's extensions, with BasicConstraints CA:FALSE plus a path length
    read as a plain end-entity constraint. The issuing paths set their own
    BasicConstraints, so nothing of that value is ever copied."""
    try:
        return csr.extensions
    except ValueError as exc:
        if 'path_length' not in str(exc):
            raise
    request = asn1crypto.csr.CertificationRequest.load(
        csr.public_bytes(serialization.Encoding.DER)
    )
    info = request['certification_request_info']
    attributes = []
    for attribute in info['attributes']:
        kind = attribute['type'].native
        if kind not in _EXTENSION_ATTRIBUTES:
            attributes.append(attribute)
            continue
        values = []
        sets = attribute['values']
        if isinstance(sets, asn1crypto.core.Any):
            # asn1crypto knows no spec for Microsoft's attribute
            sets = _ExtensionSets.load(sets.dump())
        for extension_set in sets:
            extensions = []
            for extension in extension_set:
                if extension['extn_id'].native == 'basic_constraints':
                    extension = asn1crypto.x509.Extension({
                        'extn_id': 'basic_constraints',
                        'critical': extension['critical'].native,
                        'extn_value': asn1crypto.x509.BasicConstraints({'ca': False}),
                    })
                extensions.append(extension)
            values.append(asn1crypto.x509.Extensions(extensions))
        attributes.append(asn1crypto.csr.CRIAttribute({
            'type': 'extension_request', 'values': values,
        }))
    info['attributes'] = asn1crypto.csr.CRIAttributes(attributes)
    # The signature no longer covers the info: this copy is read for its
    # extensions only, proof of possession was checked on the original.
    return x509.load_der_x509_csr(request.dump()).extensions


def extensions_of(cert_or_csr) -> x509.Extensions:
    """Extensions of a certificate, or of a CSR read the tolerant way."""
    if isinstance(cert_or_csr, x509.CertificateSigningRequest):
        return csr_extensions(cert_or_csr)
    return cert_or_csr.extensions
