from utils.revocation_reasons import REASON_FLAGS

DEFAULT_VALIDITY_DAYS = 7

# The shared reason table (utils/revocation_reasons.py). Kept under this name
# for the CRL builder and for services/msca/crl_sync.py, which inverts it to
# read a Windows CA's CRL back into UCM's own spellings. ``removeFromCRL``
# belongs here: a delta CRL is the only place RFC 5280 §5.3.1 allows it.
REASON_MAP = dict(REASON_FLAGS)
