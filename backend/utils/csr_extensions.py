"""Reading a CSR's extensions when one of them is malformed the Windows way."""
import asn1crypto.csr
import asn1crypto.x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def csr_extensions(csr: x509.CertificateSigningRequest) -> x509.Extensions:
    """The CSR's extensions, tolerating BasicConstraints CA:FALSE with a path length.

    The Windows NDES client writes that shape and cryptography refuses the whole
    extension set for it. The constraint is read as a plain end-entity one; the
    issuing paths set their own BasicConstraints and never copy the request's.
    """
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
        if attribute['type'].native != 'extension_request':
            attributes.append(attribute)
            continue
        values = []
        for extension_set in attribute['values']:
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
