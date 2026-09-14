"""Why a CSR that looks intact fails ``is_signature_valid``.

``cryptography``'s ``CertificateSigningRequest.is_signature_valid`` reports
False for a SHA-1-signed CSR even when the signature is mathematically valid
(confirmed by verifying the same signature manually with
``public_key.verify(..., hashes.SHA1())``) -- it isn't reporting tampering,
it's refusing to vouch for a weak hash algorithm.

That deserves a specific message rather than the generic "signature invalid"
one, which reads as if the request were corrupted, and it is a common case:
Windows' certreq.exe defaults to SHA-1 unless an INF explicitly sets
HashAlgorithm=sha256. EST and WSTEP each carried a byte-identical copy of this;
it lives here so every enrollment door can say the same thing.
"""

WEAK_CSR_HASH_ALGORITHMS = {'md5', 'sha1'}


def weak_csr_hash_algorithm(csr):
    """The CSR's signature hash algorithm name, if it's one of the weak ones
    ``is_signature_valid`` refuses to validate. None otherwise (including when
    the algorithm can't be determined at all, e.g. Ed25519)."""
    try:
        algo = csr.signature_hash_algorithm
    except Exception:
        return None
    if algo is not None and algo.name in WEAK_CSR_HASH_ALGORITHMS:
        return algo.name
    return None
