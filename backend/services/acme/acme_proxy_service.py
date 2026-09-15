"""
ACME Proxy Service
Acts as a gateway between internal ACME clients and upstream ACME providers (Let's Encrypt)
"""
import json
import base64
import re
import requests
import secrets
import logging
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, Union

from flask import current_app
from sqlalchemy import and_, or_

from utils.san_parse import strip_wildcard

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils as asym_utils
from cryptography.hazmat.backends import default_backend

from models import db, SystemConfig, DnsProvider
from security.encryption import encrypt_text, decrypt_text
from utils.datetime_utils import utc_isoformat
from services.acme.acme_client_service import AcmeClientService
from services.acme import outbound
from services.acme.acme_proxy_account import (
    resolve_proxy_account,
    legacy_upstream_directory_url,
)
from services.acme.dns_selfcheck import (
    acme_allow_loopback_upstream,
    dns_propagation_timeout,
    wait_for_txt,
)
from utils.acme_debug import acme_log
from utils import ssrf_protection

logger = logging.getLogger(__name__)


class ProxyDns01OnlyError(ValueError):
    """The ACME proxy deliberately supports DNS identifiers/DNS-01 only."""


class ProxyResourceNotFoundError(LookupError):
    """No local proxy order tracks the requested upstream resource."""


class ProxyChallengeIdentifierError(RuntimeError):
    """The identifier a challenge validates could not be established.

    Fails closed: guessing an identifier on a multi-SAN order would publish the
    DNS-01 TXT record under the wrong name. Carried as its own type so the
    endpoint answers with a problem document that names the cause.
    """


# --- Process-level caches -------------------------------------------------
#
# AcmeProxyService is instantiated per request, so anything memoized on the
# instance is always cold: every proxied call used to pay an extra
# GET /directory plus a HEAD /new-nonce upstream. These caches are advisory —
# every lookup falls back to the upstream round-trip on a miss, so a restart or
# a second worker process only costs performance, never correctness.

_DIRECTORY_CACHE_TTL_SEC = 300
_FINALIZE_CACHE_TTL_SEC = 3600
_CHALLENGE_ORDER_CACHE_TTL_SEC = 3600
_CERT_SCAN_LIMIT = 25

# RFC 8288 link-value: '<uri>' followed by its own ';'-separated parameters.
_LINK_VALUE_RE = re.compile(r'<([^>]*)>([^,]*)')
# 'rel' may be quoted or bare; the trailing guard keeps rel="upstream" out.
_LINK_REL_UP_RE = re.compile(
    r'rel\s*=\s*(?:"up"|\'up\'|up(?=\s*(?:;|$)))', re.IGNORECASE
)

_cache_lock = threading.Lock()


def _dns01_txt_value(key_authorization: str) -> str:
    """RFC 8555 section 8.4: TXT value = b64url(SHA-256(key authorization))."""
    import base64
    import hashlib
    digest = hashlib.sha256(key_authorization.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
_directory_cache = {}        # upstream directory URL -> (stored_at, directory)
_finalize_url_cache = {}     # upstream order URL     -> (stored_at, finalize URL)
_challenge_order_cache = {}  # per-requester challenge key -> (stored_at, (order id, domain))


def _cache_get(store: dict, key: str, ttl: int):
    """Return a live cache entry, dropping it when expired."""
    if not key:
        return None
    with _cache_lock:
        entry = store.get(key)
        if not entry:
            return None
        stored_at, value = entry
        if time.monotonic() - stored_at > ttl:
            store.pop(key, None)
            return None
        return value


def _cache_put(store: dict, key: str, value, max_entries: int = 512) -> None:
    """Store a cache entry, evicting the oldest one when the bound is hit."""
    if not key:
        return
    with _cache_lock:
        if key not in store and len(store) >= max_entries:
            oldest = min(store.items(), key=lambda item: item[1][0])[0]
            store.pop(oldest, None)
        store[key] = (time.monotonic(), value)


# The reserve lives in services/acme/outbound, so the client side draws from
# and feeds the same one; these names stay because callers and tests use them.
_nonce_pool_pop = outbound.nonce_pool_pop
_nonce_pool_push = outbound.nonce_pool_push


def reset_proxy_caches() -> None:
    """Drop every process-level cache.

    These caches outlive a single request by design, which also means they
    outlive a single test: two test modules that stub the same upstream
    directory URL with different payloads would otherwise see each other's
    entries. Call this from an autouse fixture, and after changing an upstream
    account's directory URL in place.
    """
    with _cache_lock:
        _directory_cache.clear()
        _finalize_url_cache.clear()
        _challenge_order_cache.clear()
    outbound.reset_nonce_pool()


class AcmeProxyService:
    # Default upstream (Let's Encrypt Staging for safety by default, user can change)
    DEFAULT_UPSTREAM = "https://acme-staging-v02.api.letsencrypt.org/directory"
    # Production: https://acme-v02.api.letsencrypt.org/directory

    def __init__(self, base_url: str, account_id: int = None):
        self.base_url = base_url.rstrip('/')
        self._account_id = account_id
        self._account = None
        self._key_loaded = False
        self._private_key = None
        self._account_jwk = None
        self.verify_ssl = self._get_verify_ssl()
        self.directory = None
        if not self.verify_ssl:
            logger.warning(
                "ACME proxy upstream SSL verification disabled by settings "
                "(acme.proxy.verify_ssl=false)."
            )
        # Resolve the upstream directory URL eagerly (cheap: config read or one
        # DB lookup). For an explicit account_id (slug routes) the row MUST
        # exist. For the legacy default route we fall back to the configured /
        # Let's Encrypt staging URL when no account is configured yet, so that
        # /directory and /new-nonce keep working on a fresh install (regression
        # v2.185: resolving the account in __init__ broke /directory with a 500
        # before any CA account was added).
        try:
            self.upstream_directory_url = self.account.directory_url
        except RuntimeError:
            if account_id is not None:
                raise  # explicit/slug request must reference a real account
            self.upstream_directory_url = legacy_upstream_directory_url()
        # Lazy-load account URL — don't register in constructor
        # This prevents /directory from failing when upstream is unreachable
        self._account_url = None

    @property
    def account(self):
        """Linked AcmeClientAccount, resolved lazily.

        Resolved on first access so that /directory and /new-nonce (which only
        need ``upstream_directory_url``) work even when no CA account is
        configured. Key-bearing operations (new-account, new-order, signing)
        trigger the resolution and will raise the helpful "No external ACME CA
        account configured" error if none exists.
        """
        if self._account is None:
            self._account = resolve_proxy_account(self._account_id)
        return self._account

    @account.setter
    def account(self, value):
        self._account = value

    @property
    def private_key(self):
        self._ensure_account_key()
        return self._private_key

    @private_key.setter
    def private_key(self, value):
        self._private_key = value

    @property
    def account_jwk(self):
        self._ensure_account_key()
        return self._account_jwk

    @account_jwk.setter
    def account_jwk(self, value):
        self._account_jwk = value

    def _ensure_account_key(self):
        """Load the upstream account private key on first use (requires the
        linked AcmeClientAccount to be configured)."""
        if self._key_loaded:
            return
        self._private_key, self._account_jwk = self._load_or_create_account_key()
        self._key_loaded = True

    @property
    def account_url(self):
        """Lazy-load account URL — only register when actually needed"""
        if self._account_url is None:
            self._account_url = self._get_upstream_account_url()
        return self._account_url

    @account_url.setter
    def account_url(self, value):
        self._account_url = value

    def _decode_proxy_id(self, id_b64: str) -> str:
        """Decode a client-supplied proxy ID (base64url of upstream URL) and
        validate that the URL targets the configured upstream ACME host.

        This prevents SSRF / credential-relay attacks where a malicious client
        crafts an ID that decodes to an arbitrary URL — `_post_with_account`
        would otherwise sign a JWS with the upstream account key and POST it
        to that URL, leaking credentials.
        """
        from urllib.parse import urlparse
        try:
            id_b64_padded = id_b64 + '=' * (-len(id_b64) % 4)
            url = base64.urlsafe_b64decode(id_b64_padded).decode('utf-8', errors='strict')
        except Exception:
            raise ValueError("Invalid proxy ID encoding")
        parsed = urlparse(url)
        if parsed.scheme not in ('https',):
            raise ValueError("Proxy ID does not target https")
        upstream_host = urlparse(self.upstream_directory_url).hostname
        if not upstream_host or parsed.hostname != upstream_host:
            logger.warning(
                "ACME proxy: rejected ID with foreign host %s (expected %s)",
                parsed.hostname, upstream_host
            )
            raise ValueError("Proxy ID host does not match upstream ACME server")
        return url

    @staticmethod
    def _proxy_id(url: str) -> str:
        """base64url proxy ID for an upstream URL (inverse of _decode_proxy_id)."""
        return base64.urlsafe_b64encode(url.encode()).rstrip(b'=').decode()

    @staticmethod
    def _strip_wildcard(domain: str) -> str:
        """Drop a leading '*.' label (see utils.san_parse.strip_wildcard)."""
        return strip_wildcard(domain)

    @staticmethod
    def _get_verify_ssl() -> bool:
        """Get proxy upstream TLS verification setting (default: True)."""
        cfg = SystemConfig.query.filter_by(key='acme.proxy.verify_ssl').first()
        if not cfg or cfg.value is None:
            return True
        parsed = str(cfg.value).strip().lower()
        if parsed in ('true', '1', 'yes', 'on'):
            return True
        if parsed in ('false', '0', 'no', 'off'):
            return False
        logger.warning(
            "Invalid acme.proxy.verify_ssl value '%s'; falling back to secure default (True).",
            cfg.value
        )
        return True

    @staticmethod
    def _prune_replaced_certificates_enabled() -> bool:
        """Opt-in purge of superseded proxy-imported certificates (#240).

        Default: disabled — proxy-issued certificates are inventoried forever
        unless the operator opts in.
        """
        cfg = SystemConfig.query.filter_by(
            key='acme.proxy.prune_replaced_certificates').first()
        if not cfg or cfg.value is None:
            return False
        parsed = str(cfg.value).strip().lower()
        if parsed in ('true', '1', 'yes', 'on'):
            return True
        if parsed in ('false', '0', 'no', 'off'):
            return False
        logger.warning(
            "Invalid acme.proxy.prune_replaced_certificates value '%s'; "
            "falling back to disabled.", cfg.value
        )
        return False

    def _prune_replaced_certificates(self, order, new_certificate_id: int) -> int:
        """Delete proxy-imported certificates superseded by this renewal (#240).

        Opt-in via ``acme.proxy.prune_replaced_certificates``. Only certificates
        imported through an *older proxy order with the exact same domain set*
        (``source='acme_client'``) are removed; revoked certificates are always
        kept (inventory/revocation history), and certificates not issued through
        the proxy are never touched. Best-effort: never raises, failures are
        logged.
        """
        if not self._prune_replaced_certificates_enabled():
            return 0

        from models import AcmeClientOrder, Certificate
        from services.cert_service import CertificateService

        old_orders = AcmeClientOrder.query.filter(
            AcmeClientOrder.is_proxy_order.is_(True),
            AcmeClientOrder.domains == order.domains,
            AcmeClientOrder.id != order.id,
            AcmeClientOrder.certificate_id.isnot(None),
        ).all()

        pruned = 0
        for old_order in old_orders:
            cert = db.session.get(Certificate, old_order.certificate_id)
            if cert is None or cert.id == new_certificate_id:
                continue
            if cert.revoked or cert.source != 'acme_client':
                # Revoked: keep for CRL/history. Non-proxy origin: never touch.
                continue
            # Detach every order still pointing at this certificate (FK safety)
            for ref in AcmeClientOrder.query.filter_by(certificate_id=cert.id).all():
                ref.certificate_id = None
            try:
                db.session.flush()
            except Exception as e:
                db.session.rollback()
                logger.error(
                    f"[ACME Proxy] Prune: failed to detach orders from "
                    f"certificate {cert.id}: {e}"
                )
                continue
            if CertificateService.delete_certificate(cert.id, username='acme_proxy'):
                pruned += 1
            else:
                logger.error(
                    f"[ACME Proxy] Prune: failed to delete certificate {cert.id}"
                )
        if pruned:
            logger.info(
                "[ACME Proxy] Pruned %d superseded certificate(s) for domains %s",
                pruned, order.domains,
            )
        return pruned

    def _load_or_create_account_key(self):
        """Load upstream account private key from the linked AcmeClientAccount."""
        from services.acme.acme_client_service import AcmeClientService

        client = AcmeClientService(account=self.account)
        private_key = client._get_account_key()
        jwk_dict = client._build_jwk(private_key)
        return private_key, jwk_dict

    def _detect_key_algorithm(self) -> str:
        from services.acme.acme_client_service import AcmeClientService
        return AcmeClientService(account=self.account)._detect_key_algorithm(self.private_key)

    def _sign_data(self, data: bytes) -> bytes:
        from services.acme.acme_client_service import AcmeClientService
        return AcmeClientService(account=self.account)._sign_data(self.private_key, data)

    def _jwk_thumbprint(self) -> str:
        from services.acme.acme_client_service import AcmeClientService
        return AcmeClientService(account=self.account)._jwk_thumbprint(self.private_key)

    def _refresh_account_session(self) -> None:
        """Re-bind the linked AcmeClientAccount to the current SQLAlchemy session.

        Kept for callers that reuse a service instance across app contexts.
        Background threads started by this service no longer rely on it: they
        build their own AcmeProxyService instead, because rebinding shared
        instance state from a worker thread raced with the request thread (and
        with the sibling threads a multi-domain order starts).
        """
        from models.acme_client_account import AcmeClientAccount

        account_id = self.account.id
        self._account = db.session.get(AcmeClientAccount, account_id)
        if not self._account:
            raise RuntimeError(f"ACME proxy account {account_id} not found")
        if self._account_url is None:
            self._account_url = self._account.account_url

    def _get_upstream_account_url(self):
        """Get or register account URL on the linked AcmeClientAccount row."""
        if self.account.account_url:
            return self.account.account_url
        return self._register_upstream_account()

    @staticmethod
    def _is_public_email_domain(email: str) -> bool:
        """Best-effort check: reject obviously non-public TLDs that will be rejected by
        Let's Encrypt's Public Suffix List check. Not a full PSL — rejects common
        internal/dev TLDs. Real PSL validation happens upstream anyway."""
        if not email or '@' not in email:
            return False
        domain = email.rsplit('@', 1)[-1].strip().lower()
        if '.' not in domain:
            return False
        private_tlds = {'local', 'lan', 'home', 'internal', 'intranet',
                        'corp', 'localdomain', 'localhost', 'example', 'test',
                        'invalid', 'onion'}
        tld = domain.rsplit('.', 1)[-1]
        return tld not in private_tlds

    def _resolve_contact_email(self) -> Optional[str]:
        """Resolve the contact email to use for upstream account registration.
        Priority:
          1. Email on the linked AcmeClientAccount row
          2. Legacy acme.proxy_email (validated)
          3. None — caller must handle (LE accepts registration without contact)
        """
        if self.account.email:
            email = self.account.email.strip()
            if self._is_public_email_domain(email):
                return email
            logger.warning(
                "Account email '%s' has non-public TLD; trying legacy proxy_email.",
                email,
            )
        cfg = SystemConfig.query.filter_by(key='acme.proxy_email').first()
        if cfg and cfg.value:
            email = cfg.value.strip()
            if self._is_public_email_domain(email):
                return email
            logger.warning(
                "Configured acme.proxy_email '%s' has non-public TLD; "
                "registering without contact email.", email
            )
        return None

    def _register_upstream_account(self):
        """Register the linked AcmeClientAccount with the upstream CA."""
        from services.acme.acme_client_service import AcmeClientService

        contact_email = self._resolve_contact_email()
        if not contact_email:
            # RFC 8555 makes `contact` optional and Let's Encrypt accepts
            # contact-less registrations — don't block issuance when the only
            # available email has a non-public TLD (.lan/.local).
            logger.warning(
                "No public contact email available for the proxy upstream "
                "account; registering without a contact."
            )

        client = AcmeClientService(account=self.account)
        success, message, account_url = client.register_account(contact_email)
        if not success:
            raise RuntimeError(message)

        self._account_url = account_url
        return account_url

    @staticmethod
    def _validate_outbound_acme_url(url: str) -> None:
        """Block loopback/cloud-metadata targets for upstream ACME sub-URLs.

        Loopback is allowed only when the operator opts in for a colocated
        upstream (see acme_allow_loopback_upstream); metadata stays blocked."""
        outbound.validate_outbound_acme_url(url)

    def _http_timeout(self) -> int:
        """The configured upstream HTTP timeout, without demanding an account.

        ``self.account`` resolves lazily and raises when no CA account is
        configured, and /directory and /new-nonce answer without one — so this
        reads the already-resolved account and falls back to the default
        rather than forcing the resolution and turning those into a 500.
        """
        from models.acme_client_account import AcmeClientAccount
        account = self._account
        if account is not None:
            return account.get_http_timeout_sec()
        return AcmeClientAccount.DEFAULT_HTTP_TIMEOUT_SEC

    def _ensure_directory(self):
        """Fetch upstream directory (process-cached for _DIRECTORY_CACHE_TTL_SEC).

        The service is per-request, so without the cache every proxied call
        paid an extra upstream GET /directory.
        """
        if self.directory:
            return
        cached = _cache_get(
            _directory_cache, self.upstream_directory_url, _DIRECTORY_CACHE_TTL_SEC
        )
        if cached:
            # Hand out a copy: the cached mapping is shared by every request
            # and thread using this upstream.
            self.directory = dict(cached)
            return
        self._validate_outbound_acme_url(self.upstream_directory_url)
        try:
            resp = ssrf_protection.safe_request_get(
                self.upstream_directory_url,
                allow_loopback=acme_allow_loopback_upstream(),
                timeout=self._http_timeout(),
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
            self.directory = resp.json()
            _cache_put(
                _directory_cache, self.upstream_directory_url, dict(self.directory)
            )
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(
                f"Cannot connect to upstream ACME server at {self.upstream_directory_url}: {e}"
            )
        except requests.exceptions.Timeout:
            raise RuntimeError(
                f"Timeout connecting to upstream ACME server at {self.upstream_directory_url}"
            )
        except requests.exceptions.HTTPError as e:
            raise RuntimeError(
                f"Upstream ACME server returned error: {e.response.status_code} {e.response.reason}"
            )

    def _get_nonce(self):
        """Get nonce from upstream, reusing pooled Replay-Nonce values first.

        Every upstream response carries a fresh Replay-Nonce (RFC 8555 §6.5),
        so harvesting them removes one HEAD /new-nonce round-trip per proxied
        request. Pooled values are single-use, and a stale one is still covered
        by the badNonce retry in _post_jws.
        """
        pooled = _nonce_pool_pop(self.upstream_directory_url)
        if pooled:
            return pooled
        self._ensure_directory()
        return outbound.fetch_nonce(
            self.directory['newNonce'],
            timeout=self._http_timeout(),
            verify=self.verify_ssl,
        )

    def _sign_and_post(self, url: str, payload, nonce: str, kid: str = None) -> requests.Response:
        """Build a JWS with the given nonce and POST it once."""
        alg = self._detect_key_algorithm()
        if kid:
            protected = {"alg": alg, "kid": kid, "nonce": nonce, "url": url}
        else:
            protected = {"alg": alg, "jwk": self.account_jwk, "nonce": nonce, "url": url}

        if payload == "":
            payload_json = b""
        else:
            payload_json = json.dumps(payload).encode('utf-8')

        protected_json = json.dumps(protected).encode('utf-8')

        payload_b64 = base64.urlsafe_b64encode(payload_json).rstrip(b'=').decode('utf-8')
        protected_b64 = base64.urlsafe_b64encode(protected_json).rstrip(b'=').decode('utf-8')

        signing_input = f"{protected_b64}.{payload_b64}".encode('utf-8')
        sig = self._sign_data(signing_input)

        data = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": base64.urlsafe_b64encode(sig).rstrip(b'=').decode('utf-8')
        }

        headers = {"Content-Type": "application/jose+json"}
        self._validate_outbound_acme_url(url)
        resp = ssrf_protection.safe_request_post(
            url,
            allow_loopback=acme_allow_loopback_upstream(),
            json=data,
            headers=headers,
            timeout=self._http_timeout(),
            verify=self.verify_ssl
        )
        # Harvest the fresh nonce for the next request. HTTP 400 is skipped: a
        # badNonce error's Replay-Nonce is consumed by the retry below, and
        # pooling it too would hand the same nonce to two requests.
        if resp.status_code != 400:
            _nonce_pool_push(
                self.upstream_directory_url, resp.headers.get('Replay-Nonce')
            )
        return resp

    def _post_jws(self, url: str, payload: Union[Dict, str], kid: str = None) -> requests.Response:
        """Sign and post JWS to upstream, with automatic badNonce retry (RFC 8555 §6.5).

        Some upstream CAs (Pebble, HARICA, strict implementations) reject
        nonces that LE staging would accept. On badNonce, the server MUST
        return a fresh nonce in Replay-Nonce and the client MUST retry.
        """
        nonce = self._get_nonce()
        resp = self._sign_and_post(url, payload, nonce, kid=kid)

        # RFC 8555 §6.5: retry once on badNonce using the fresh nonce
        # returned in the error response's Replay-Nonce header.
        if resp.status_code == 400:
            try:
                err = resp.json()
                if err.get('type') == 'urn:ietf:params:acme:error:badNonce':
                    fresh_nonce = resp.headers.get('Replay-Nonce')
                    if fresh_nonce:
                        logger.warning(f"Upstream rejected nonce on {url}, retrying with fresh nonce")
                        resp = self._sign_and_post(url, payload, fresh_nonce, kid=kid)
            except (json.JSONDecodeError, ValueError):
                pass

        return resp

    def _post_with_account(self, url: str, payload) -> requests.Response:
        """Post JWS with account KID, auto-re-registering if account is stale.

        Upstream CAs (especially LE staging) may invalidate accounts.
        This detects 401/403 "Account is not valid" and re-registers automatically.
        """
        resp = self._post_jws(url, payload, kid=self.account_url)

        if resp.status_code in [401, 403]:
            try:
                error_data = resp.json()
                detail = error_data.get('detail', '')
                if 'not valid' in detail.lower() or 'deactivated' in detail.lower():
                    logger.warning(f"Upstream account invalid ({detail}), re-registering...")

                    # Clear stale account URL on the linked row
                    self.account.account_url = None
                    self._account_url = None
                    try:
                        db.session.commit()
                    except Exception as e:
                        db.session.rollback()
                        logger.error(f"Failed to clear stale account URL: {e}")
                        return resp

                    # Re-register with upstream
                    self.account_url = self._register_upstream_account()
                    logger.info(f"Re-registered upstream account: {self.account_url}")

                    # Retry original request with new account
                    resp = self._post_jws(url, payload, kid=self.account_url)
            except (json.JSONDecodeError, KeyError):
                pass
            except Exception as e:
                logger.error(f"Account re-registration failed: {e}")

        return resp

    # --- Proxy Methods ---

    def revoke_certificate(self, certificate, reason: int = 0) -> requests.Response:
        """Revoke a proxy-issued certificate with the linked upstream account."""
        client = AcmeClientService(account=self.account)
        if self.directory is not None:
            client.directory = self.directory
        return client.revoke_certificate(certificate, reason)

    def get_directory(self):
        """Return proxy directory.

        Override upstream meta.externalAccountRequired with local UCM EAB
        policy so clients (win-acme, certbot, acme.sh) know they MUST send
        an externalAccountBinding when registering against this proxy.
        Issue #112: previously the proxy passed upstream's meta as-is, which
        for Let's Encrypt does not require EAB, so clients sent registrations
        without EAB and were accepted.
        """
        from models import SystemConfig
        self._ensure_directory()
        meta = dict(self.directory.get('meta', {}))
        eab_cfg = SystemConfig.query.filter_by(key='acme_eab_required').first()
        eab_required = (eab_cfg.value if eab_cfg else 'false').lower() == 'true'
        meta['externalAccountRequired'] = eab_required
        directory = {
            "newNonce": f"{self.base_url}/new-nonce",
            "newAccount": f"{self.base_url}/new-account",
            "newOrder": f"{self.base_url}/new-order",
            "revokeCert": f"{self.base_url}/revoke-cert",
            "keyChange": f"{self.base_url}/key-change",
            "meta": meta,
        }
        # Advertise ARI (RFC 9773) when the upstream does. Served locally
        # from the UCM database — proxy-issued certs are stored on import,
        # so no upstream round-trip and no upstream host leak.
        #
        # RFC 9773 §3/§4.1: the directory entry is the BASE URL; clients
        # append "/<certID>" to form the full request URL. Publishing the
        # literal "<certID>" placeholder here would double the path segment.
        if 'renewalInfo' in self.directory:
            directory['renewalInfo'] = f"{self.base_url}/renewal-info"
        return directory

    def new_nonce(self):
        """Proxy new-nonce"""
        self._ensure_directory()
        # Just return a local nonce or fetch upstream?
        # ACME clients expect a nonce they can use for the next request.
        # But the next request will go to US. So we should issue OUR nonce.
        # And when we forward to upstream, we fetch an UPSTREAM nonce.
        # So: Standard local nonce logic.
        from services.acme import AcmeService
        svc = AcmeService(self.base_url)
        return svc.generate_nonce()

    def new_order(
        self,
        identifiers,
        not_before=None,
        not_after=None,
        client_thumbprint=None,
        replaces=None,
    ):
        """Proxy new-order with domain validation and RFC 9773 replacement."""
        from api.v2.acme_domains import find_provider_for_domain
        from models import AcmeClientOrder

        if not identifiers:
            raise ValueError("identifiers must be a non-empty list")

        self._ensure_directory()

        # The proxy performs validation itself through configured DNS providers.
        # Never forward IP identifiers: RFC 8738 requires HTTP-01/TLS-ALPN-01,
        # neither of which can be fulfilled by this DNS-01-only gateway.
        domains = []
        for ident in identifiers:
            if not isinstance(ident, dict) or not ident.get('value'):
                raise ValueError('Each identifier must contain type and value')
            if ident.get('type') != 'dns':
                raise ProxyDns01OnlyError(
                    'The ACME proxy supports DNS identifiers with dns-01 only; '
                    'IP identifiers are not supported.'
                )
            domains.append(ident['value'])

        # Verify each domain has a DNS provider configured
        domain_providers = {}
        for domain in domains:
            # Remove wildcard prefix for lookup (removeprefix not lstrip — chars vs prefix)
            lookup_domain = self._strip_wildcard(domain)
            provider = find_provider_for_domain(lookup_domain)
            if not provider:
                raise Exception(f"No DNS provider configured for domain: {domain}. Configure it in ACME > Domains.")
            domain_providers[domain] = provider

        # Same-account dedupe (#303 minor 4): a client that retries new-order
        # for the same identifiers (Traefik does) must get its still-pending
        # order back, like upstream CAs do, instead of opening a new upstream
        # order every time. Cross-account sharing is #310's job — the match is
        # strictly on this requester's own orders.
        existing = self._find_reusable_pending_order(domains, client_thumbprint)
        if existing is not None:
            return existing

        # Forward to upstream Let's Encrypt
        payload = {
            "identifiers": identifiers,
            "notBefore": utc_isoformat(not_before),
            "notAfter": utc_isoformat(not_after)
        }
        # Filter None and forward RFC 9773 `replaces` only when supported.
        payload = {k: v for k, v in payload.items() if v is not None}
        if replaces and self.directory.get('renewalInfo'):
            payload['replaces'] = replaces

        resp = self._post_with_account(self.directory['newOrder'], payload)

        if resp.status_code != 201:
            raise Exception(f"Upstream error: {resp.text}")

        upstream_order = resp.json()
        upstream_location = resp.headers['Location']

        # Get upstream authz URLs for later matching
        upstream_authz_urls = upstream_order.get('authorizations', [])

        # Resolve linked local AcmeAccount from the client JWK thumbprint.
        # The proxy's /new-account handler already created (or upserted) an
        # AcmeAccount with this thumbprint, so the lookup should always hit
        # for compliant clients. If it misses, we leave account_id NULL —
        # the order still works, it just won't show in the account detail.
        linked_account_id = None
        if client_thumbprint:
            try:
                from models import AcmeAccount
                acct = AcmeAccount.query.filter_by(
                    jwk_thumbprint=client_thumbprint
                ).first()
                if acct is not None:
                    linked_account_id = acct.account_id
            except Exception as e:
                logger.warning(
                    "ACME proxy: failed to resolve local account for "
                    "thumbprint=%s: %s", client_thumbprint[:12] if client_thumbprint else None, e
                )

        # Store order in database for tracking
        order = AcmeClientOrder(
            domains=json.dumps(domains),
            environment='staging' if 'staging' in self.upstream_directory_url else 'production',
            challenge_type='dns-01',
            status='pending',
            order_url=upstream_location,
            upstream_order_url=upstream_location,
            upstream_authz_urls=json.dumps(upstream_authz_urls),
            is_proxy_order=True,
            client_jwk_thumbprint=client_thumbprint,
            account_id=linked_account_id,
            acme_client_account_id=self.account.id,
            # Use first domain's provider (provider dict contains 'provider' key with model)
            dns_provider_id=list(domain_providers.values())[0]['provider'].id if domain_providers else None
        )
        db.session.add(order)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to save ACME proxy order: {e}")
            raise

        # Remember the upstream finalize URL so finalize_order does not have to
        # re-fetch the order upstream just to read it.
        if upstream_order.get('finalize'):
            _cache_put(
                _finalize_url_cache, upstream_location, upstream_order['finalize']
            )

        # Rewrite URLs in response to point to Proxy
        return self._rewrite_order_response(upstream_order, upstream_location)

    def _rewrite_order_response(self, upstream_order, upstream_location):
        """Rewrite upstream URLs (authorizations, finalize) to proxy URLs."""
        order_id = self._proxy_id(upstream_location)
        upstream_order['authorizations'] = [
            f"{self.base_url}/authz/{self._proxy_id(authz_url)}"
            for authz_url in upstream_order['authorizations']
        ]
        upstream_order['finalize'] = f"{self.base_url}/order/{order_id}/finalize"
        return upstream_order, order_id

    def _client_txt_values(self, order, key_authz, upstream_value,
                           authz_url=None):
        """dns-01 TXT values computed with the CLIENT thumbprints of every
        sibling order sharing the current upstream authz (#306/#307), so
        client-side propagation pre-checks can succeed. The upstream value is
        excluded; failures return an empty list (publishing the client values
        is best-effort)."""
        values = []
        try:
            token = key_authz.split('.', 1)[0]
            siblings = [order]
            urls = json.loads(order.upstream_authz_urls) if order.upstream_authz_urls else []
            current_authz_url = authz_url or (urls[0] if urls else None)
            if current_authz_url:
                siblings = self._orders_by_authz_url(current_authz_url) or [order]
            seen = set()
            for sibling in siblings:
                thumb = getattr(sibling, 'client_jwk_thumbprint', None)
                if not thumb or thumb in seen:
                    continue
                seen.add(thumb)
                value = _dns01_txt_value(f"{token}.{thumb}")
                if value != upstream_value:
                    values.append(value)
        except Exception as exc:
            logger.warning(f"Could not compute client TXT values: {exc}")
            return []
        return values

    def _find_reusable_pending_order(self, domains, client_thumbprint):
        """Return the rewritten still-pending order of this requester for the
        exact same identifier set, or None (#303 minor 4).

        The upstream order is re-fetched to confirm it is still ``pending``;
        any doubt (fetch failure, other status, missing thumbprint) falls
        through to creating a fresh order.
        """
        from models import AcmeClientOrder

        if not client_thumbprint:
            return None
        wanted = sorted(domains)
        candidates = (AcmeClientOrder.query
                      .filter_by(is_proxy_order=True, status='pending',
                                 client_jwk_thumbprint=client_thumbprint)
                      .order_by(AcmeClientOrder.id.desc())
                      .limit(20).all())
        for order in candidates:
            if sorted(order.domains_list or []) != wanted:
                continue
            upstream_url = order.upstream_order_url or order.order_url
            if not upstream_url:
                continue
            try:
                resp = self._post_with_account(upstream_url, "")
                if resp.status_code != 200:
                    continue
                upstream_order = resp.json()
            except Exception as exc:
                logger.debug(f"Pending-order reuse: upstream fetch failed: {exc}")
                continue
            if upstream_order.get('status') != 'pending':
                continue
            logger.info(
                "[ACME Proxy] Reusing pending order %s for %s (same account, "
                "same identifiers)", order.id, ', '.join(wanted),
            )
            if upstream_order.get('finalize'):
                _cache_put(_finalize_url_cache, upstream_url,
                           upstream_order['finalize'])
            return self._rewrite_order_response(upstream_order, upstream_url)
        return None

    @staticmethod
    def _verify_order_ownership(local_order, requester_account_id=None,
                                requester_thumbprint=None, resource='Order'):
        """Refuse serving an owner-bound proxy order to another account (#260).

        Orders carry their owner's local ACME account id and/or client JWK
        thumbprint since creation. An owner-bound order requires a *positive*
        match on one of those fields: the absence of a contradiction is not
        enough, otherwise a half-populated binding (an account row without a
        stored thumbprint, a thumbprint that resolved to no account) would
        silently authorize any verified requester. Orders with no owner binding
        at all (legacy rows created before ownership tracking) are served as
        before.

        Raises PermissionError when ownership cannot be established.
        """
        if local_order is None:
            raise PermissionError(f"{resource} does not belong to this account")
        if not (local_order.account_id or local_order.client_jwk_thumbprint):
            return
        matched = bool(
            (local_order.account_id
             and local_order.account_id == requester_account_id)
            or (local_order.client_jwk_thumbprint
                and local_order.client_jwk_thumbprint == requester_thumbprint)
        )
        if matched:
            return
        if AcmeProxyService._owner_matches_via_account_row(
            local_order, requester_account_id, requester_thumbprint
        ):
            return
        if not requester_account_id and not requester_thumbprint:
            denied = 'no requester identity'
        elif requester_account_id and local_order.account_id and \
                local_order.account_id != requester_account_id:
            denied = f'requested by foreign account {requester_account_id}'
        elif local_order.client_jwk_thumbprint and requester_thumbprint and \
                local_order.client_jwk_thumbprint != requester_thumbprint:
            denied = 'JWK thumbprint mismatch'
        else:
            denied = 'no matching owner binding'
        logger.warning(
            "ACME proxy: refused %s access on order %s (%s)",
            resource.lower(), local_order.id, denied,
        )
        raise PermissionError(f"{resource} does not belong to this account")

    @staticmethod
    def _owner_matches_via_account_row(local_order, requester_account_id,
                                       requester_thumbprint):
        """Establish a positive owner match across a half-populated binding.

        An order that recorded only one of the two owner fields still belongs to
        exactly one local ACME account, so the missing half is resolved through
        the AcmeAccount row before access is refused. This keeps orders created
        before both fields were populated (or whose thumbprint never resolved to
        an account at new-order time) usable, without falling back to the old
        "no contradiction means allowed" rule. Runs only on the deny path.
        """
        from models import AcmeAccount

        try:
            if (local_order.client_jwk_thumbprint and not local_order.account_id
                    and requester_account_id):
                owner = AcmeAccount.query.filter_by(
                    jwk_thumbprint=local_order.client_jwk_thumbprint
                ).first()
                return bool(owner and owner.account_id == requester_account_id)
            if (local_order.account_id and not local_order.client_jwk_thumbprint
                    and requester_thumbprint):
                requester = AcmeAccount.query.filter_by(
                    jwk_thumbprint=requester_thumbprint
                ).first()
                return bool(requester
                            and requester.account_id == local_order.account_id)
        except Exception as exc:
            logger.warning("ACME proxy: owner reconciliation failed: %s", exc)
        return False

    @staticmethod
    def _order_authz_urls(order):
        """Upstream authz URLs recorded on a proxy order, as an exact list."""
        raw = getattr(order, 'upstream_authz_urls', None)
        if not raw:
            return []
        if isinstance(raw, list):
            urls = raw
        else:
            try:
                urls = json.loads(raw)
            except (TypeError, ValueError):
                return []
        if not isinstance(urls, list):
            return []
        return [url for url in urls if isinstance(url, str)]

    def _orders_by_authz_url(self, authz_url: str):
        """Every proxy order that recorded this exact upstream authz URL.

        The proxy signs upstream with one shared account, so Let's Encrypt
        reuses a single authorization across every downstream account that
        ordered the same domain — the URL then maps to more than one local
        order (#307).

        ``contains()`` is only a prefilter: as a LIKE '%url%' it also matches a
        *prefix* of a stored URL (".../authz-v3/99" inside ".../authz-v3/999"),
        so a client could bind a foreign authz to an order it does own and pass
        the ownership check with it. Candidate rows are therefore re-checked
        against the decoded URL list.
        """
        from models import AcmeClientOrder

        candidates = AcmeClientOrder.query.filter(
            AcmeClientOrder.is_proxy_order.is_(True),
            AcmeClientOrder.upstream_authz_urls.contains(authz_url),
        ).order_by(AcmeClientOrder.id).all()
        return [o for o in candidates if authz_url in self._order_authz_urls(o)]

    def _find_order_by_authz_url(self, authz_url: str, requester_account_id=None,
                                 requester_thumbprint=None):
        """Proxy order owning an upstream authz URL, resolved for the requester.

        When one upstream authz is shared by several local orders (#307), the
        order owned by the requester is returned so its ownership check passes;
        with no owner match the lowest-id candidate is handed back and
        _verify_order_ownership issues the denial, so #260 still holds.
        """
        return self._select_owning_order(
            self._orders_by_authz_url(authz_url),
            requester_account_id, requester_thumbprint,
        )

    @staticmethod
    def _select_owning_order(candidates, requester_account_id=None,
                             requester_thumbprint=None):
        """Pick the candidate order that belongs to the requester.

        Two passes keep the AcmeAccount reconciliation off the common path: a
        direct match on either owner field first, the half-populated-binding
        reconciliation only if that finds nothing. A single candidate, legacy
        unbound rows, or no positive match all fall through to the first
        candidate unchanged, for _verify_order_ownership to rule on.
        """
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        for order in candidates:
            if ((order.account_id
                 and order.account_id == requester_account_id)
                    or (order.client_jwk_thumbprint
                        and order.client_jwk_thumbprint == requester_thumbprint)):
                return order
        for order in candidates:
            if AcmeProxyService._owner_matches_via_account_row(
                order, requester_account_id, requester_thumbprint
            ):
                return order
        return candidates[0]

    @staticmethod
    def _challenge_cache_key(chall_url, requester_account_id=None,
                             requester_thumbprint=None):
        """Per-requester key for _challenge_order_cache.

        One upstream challenge URL resolves to a different local order per
        downstream account when the upstream authorization is shared (#307), so
        the cached (order id, domain) is scoped to the requester identity. Both
        identity fields come from the same verified JWS, so an absent and an
        empty value are equivalent here and collapse to the same key.
        """
        if not chall_url:
            return ''
        return '\x1f'.join((
            chall_url,
            str(requester_account_id or ''),
            requester_thumbprint or '',
        ))

    @staticmethod
    def _challenge_automation_started(chall_url, sibling_orders):
        """True when dns-01 automation for this upstream challenge already ran.

        The challenge is one upstream resource even when several local orders
        point at it (#307); its DNS automation must fire once, so the initiated
        flag is read across every sibling order, not only the one being served.
        """
        for order in sibling_orders or ():
            state = (order.challenges_dict or {}).get(chall_url)
            if state and state.get('status') in ('initiated', 'submitted'):
                return True
        return False

    def get_authz(self, authz_id_b64, requester_account_id=None,
                  requester_thumbprint=None):
        """Proxy authz fetch — only exposes dns-01 challenges and triggers automation.

        The proxy can only handle dns-01 validation (via DNS provider).
        http-01 and tls-alpn-01 require the upstream CA to reach the client
        directly, which doesn't work through a proxy.

        Ownership is enforced before the upstream round-trip: the authz must
        belong to a tracked proxy order owned by the requester (#260).
        """
        from api.v2.acme_domains import find_provider_for_domain

        # Fix padding + validate upstream host (anti-SSRF)
        authz_url = self._decode_proxy_id(authz_id_b64)

        # Find the proxy order that contains this authz URL — every proxy
        # order records its upstream authz URLs at creation, so an untracked
        # URL is either foreign or no longer served. One upstream authz can be
        # shared by several local orders (#307), so resolve to the requester's.
        candidates = self._orders_by_authz_url(authz_url)
        if not candidates:
            raise ProxyResourceNotFoundError("Authorization not found")
        order = self._select_owning_order(
            candidates, requester_account_id, requester_thumbprint,
        )
        self._verify_order_ownership(
            order, requester_account_id, requester_thumbprint,
            resource='Authorization',
        )

        resp = self._post_with_account(authz_url, "")

        if resp.status_code != 200:
            logger.error(f"Upstream authz fetch failed: {resp.status_code} {resp.text}")
            return None

        authz = resp.json()

        # Extract identifier (domain)
        identifier = authz.get('identifier', {})
        domain = self._strip_wildcard(identifier.get('value', ''))

        # The automation domain comes from the *upstream* response, so make sure
        # it is actually covered by the order we just authorized against before
        # anything is written into the operator's DNS zone.
        covered = {
            self._strip_wildcard(d).lower()
            for d in (order.domains_list or [])
        }
        if domain and domain.lower() not in covered:
            logger.warning(
                "ACME proxy: authz identifier %s is not covered by order %s (%s)",
                domain, order.id, sorted(covered),
            )
            raise ProxyResourceNotFoundError("Authorization not found")

        # An authorization the upstream CA has already validated (pre-validated
        # or onboarded domain, typically on an EAB-bound account) carries no
        # pending challenge and often no dns-01 at all. Nothing is left to
        # validate, so it is exposed as-is and the client goes straight to
        # finalize (#325). Otherwise only dns-01 is exposed: the proxy creates
        # the DNS record itself, while http-01/tls-alpn-01 need the upstream CA
        # to reach the client directly, which cannot work through a proxy.
        already_valid = authz.get('status') == 'valid'
        proxy_challenges = []
        for chall in authz.get('challenges', []):
            if chall.get('type') != 'dns-01' and not already_valid:
                continue
            chall_url = chall.get('url')
            if not chall_url:
                continue
            chall_id = self._proxy_id(chall_url)

            # Remember which order (and identifier) this challenge belongs to so
            # respond_challenge can authorize before any upstream round-trip.
            _cache_put(
                _challenge_order_cache,
                self._challenge_cache_key(
                    chall_url, requester_account_id, requester_thumbprint,
                ),
                (order.id, domain),
            )

            # Check if we should trigger automation for this challenge
            # We trigger it as soon as the client fetches the authorization
            if chall.get('status') == 'pending' and not already_valid:
                challenges_data = order.challenges_dict
                if not self._challenge_automation_started(chall_url, candidates):
                    # Trigger automation in background
                    token = chall.get('token')
                    jwk_thumbprint = self._get_account_thumbprint()
                    key_authz = f"{token}.{jwk_thumbprint}"

                    # Ensure DNS provider exists
                    provider_info = find_provider_for_domain(domain)
                    if provider_info:
                        app = current_app._get_current_object()
                        thread = threading.Thread(
                            target=self._bg_respond_challenge,
                            args=(app, chall_url, key_authz, domain, order.id,
                                  authz_url)
                        )
                        thread.name = f"ACMEProxy-AutoDNS-{domain}"
                        thread.daemon = True

                        # Mark as initiated to avoid redundant threads
                        challenges_data[chall_url] = {'status': 'initiated', 'started_at': datetime.now().isoformat()}
                        order.set_challenges_dict(challenges_data)
                        try:
                            db.session.commit()
                            thread.start()
                            logger.info(f"[ACME Proxy] Triggered auto-DNS for {domain} via authz fetch")
                        except Exception as e:
                            db.session.rollback()
                            logger.error(f"Failed to start auto-DNS thread: {e}")


            chall['url'] = f"{self.base_url}/challenge/{chall_id}"
            proxy_challenges.append(chall)

        if not proxy_challenges and not already_valid:
            logger.error(
                f"Upstream authz for {identifier.get('value', '?')} has no dns-01 challenge. "
                f"Available types: {[c.get('type') for c in authz.get('challenges', [])]}"
            )
            raise ProxyDns01OnlyError(
                f"Upstream CA does not offer dns-01 challenge for {identifier.get('value', '?')}. "
                "The ACME proxy only supports dns-01 validation; tls-alpn-01 is not supported."
            )
        if already_valid:
            logger.info(
                "[ACME Proxy] Upstream authorization for %s is already valid; "
                "passed through without validation", domain,
            )

        authz['challenges'] = proxy_challenges
        return authz, identifier

    def respond_challenge(self, chall_id_b64, requester_account_id=None,
                          requester_thumbprint=None):
        """Proxy challenge response. If automation is already running/done, just return status.

        Ownership is enforced before any challenge data is returned or
        automation is triggered (#260), and before the upstream call whenever
        the challenge can be mapped to an order locally. Only Let's Encrypt
        style CAs, which keep ``/acme/chall-v3/`` and ``/acme/authz-v3/`` in
        disjoint namespaces, still need the upstream fetch first: their owning
        authz is taken from the Link rel="up" header (mandatory per RFC 8555
        §7.5.1) and matched exactly against the order's recorded authz URLs.
        If neither route resolves, the request fails closed.
        """
        from api.v2.acme_domains import find_provider_for_domain

        chall_url = self._decode_proxy_id(chall_id_b64)

        # Resolve and authorize *before* any upstream call when possible, so an
        # unauthorized caller cannot make the proxy sign a request with the
        # upstream CA account key at all.
        order, domain = self._resolve_challenge_order(
            chall_url, requester_account_id, requester_thumbprint,
        )
        if order is not None:
            self._verify_order_ownership(
                order, requester_account_id, requester_thumbprint,
                resource='Challenge',
            )

        # Fetch the challenge to get token and status
        resp = self._post_with_account(chall_url, "")
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch challenge: {resp.text}")

        challenge_data = resp.json()
        token = challenge_data.get('token')
        challenge_type = challenge_data.get('type')
        status = challenge_data.get('status')

        # Last resort for CAs that do not nest challenge URLs under their authz
        # (Let's Encrypt): the authoritative authz URL from the Link rel="up"
        # header (RFC 8555 §7.5.1). The removed _find_order_for_challenge fell
        # back to the most recent pending order whenever its startswith() match
        # failed — which on LE was always — running DNS automation for an
        # unrelated domain.
        authz_url = self._upstream_authz_url_from_link(resp.headers.get('Link'))
        if order is None:
            if not authz_url:
                raise ProxyResourceNotFoundError(
                    "Challenge not found: upstream returned no Link rel=\"up\" header"
                )
            order = self._find_order_by_authz_url(
                authz_url, requester_account_id, requester_thumbprint,
            )
            if order is None:
                raise ProxyResourceNotFoundError("Challenge not found")
            self._verify_order_ownership(
                order, requester_account_id, requester_thumbprint,
                resource='Challenge',
            )
            _cache_put(
                _challenge_order_cache,
                self._challenge_cache_key(
                    chall_url, requester_account_id, requester_thumbprint,
                ),
                (order.id, None),
            )

        if status != 'pending':
            # Already processing or finished: read-only pass-through whatever
            # the challenge type. A pre-validated authorization (#325) exposes
            # its already valid http-01/tls-alpn-01 challenge and a client may
            # poll it; nothing is triggered here.
            challenge_data['url'] = f"{self.base_url}/challenge/{chall_id_b64}"
            return challenge_data, self._get_authz_link(resp.headers.get('Link'))

        if challenge_type != 'dns-01':
            raise ProxyDns01OnlyError(
                f"Unsupported challenge type: {challenge_type}. "
                "The ACME proxy only supports dns-01 validation."
            )

        # If still pending, check if automation already started — for this order
        # in get_authz, or for a sibling order sharing this upstream challenge
        # when the authz is reused across downstream accounts (#307).
        challenges_data = order.challenges_dict
        siblings = self._orders_by_authz_url(authz_url) if authz_url else [order]
        if self._challenge_automation_started(chall_url, siblings):
            # Already triggered, just return 'processing'
            challenge_data['status'] = 'processing'
            challenge_data['url'] = f"{self.base_url}/challenge/{chall_id_b64}"
            return challenge_data, self._get_authz_link(resp.headers.get('Link'))

        # Fallback: Trigger if not already triggered (should be rare now)
        if not token:
            raise RuntimeError("Challenge has no token")

        if not domain:
            domain = self._challenge_domain(order, authz_url)
            _cache_put(
                _challenge_order_cache,
                self._challenge_cache_key(
                    chall_url, requester_account_id, requester_thumbprint,
                ),
                (order.id, domain),
            )

        provider_info = find_provider_for_domain(domain)
        if not provider_info:
            raise RuntimeError(f"No DNS provider configured for domain: {domain}")

        jwk_thumbprint = self._get_account_thumbprint()
        key_authz = f"{token}.{jwk_thumbprint}"

        app = current_app._get_current_object()
        thread = threading.Thread(
            target=self._bg_respond_challenge,
            args=(app, chall_url, key_authz, domain, order.id, authz_url)
        )
        thread.name = f"ACMEProxy-DNS-{domain}"
        thread.daemon = True

        # Persist the initiated flag before the thread starts so a sibling order
        # sharing this upstream challenge (#307) does not launch a second one.
        # Mirror get_authz: only start the thread once the flag is committed.
        challenges_data[chall_url] = {
            'status': 'initiated', 'started_at': datetime.now().isoformat(),
        }
        order.set_challenges_dict(challenges_data)
        try:
            db.session.commit()
            thread.start()
        except Exception as exc:
            db.session.rollback()
            logger.error(f"Failed to start dns-01 automation: {exc}")

        challenge_data['status'] = 'processing'
        challenge_data['url'] = f"{self.base_url}/challenge/{chall_id_b64}"

        return challenge_data, self._get_authz_link(resp.headers.get('Link'))

    def _resolve_challenge_order(self, chall_url, requester_account_id=None,
                                 requester_thumbprint=None):
        """(order, identifier) for a challenge URL, without any upstream call.

        Two local routes, both exact:

        1. the mapping get_authz recorded when the client fetched the
           authorization (also carries the identifier);
        2. CAs that nest the challenge under its authorization (Boulder's
           ``/acme/authz-v3/<id>/<n>``, Pebble, step-ca) — candidate authz URLs
           are formed by dropping trailing path segments and looked up as exact
           recorded values.

        Returns (None, None) when only the upstream Link rel="up" header can
        resolve it. There is deliberately no host-only match and no "most recent
        pending order" fallback: an approximate match would run DNS automation
        against a foreign domain.
        """
        from models import AcmeClientOrder

        cached = _cache_get(
            _challenge_order_cache,
            self._challenge_cache_key(
                chall_url, requester_account_id, requester_thumbprint,
            ),
            _CHALLENGE_ORDER_CACHE_TTL_SEC,
        )
        if cached:
            order_id, domain = cached
            order = db.session.get(AcmeClientOrder, order_id)
            if order is not None:
                return order, domain

        parts = chall_url.split('/')
        # Bounded: only the two nearest parent paths, and never above
        # scheme://host/<segment>.
        for depth in range(len(parts) - 1, max(len(parts) - 3, 3), -1):
            order = self._find_order_by_authz_url(
                '/'.join(parts[:depth]),
                requester_account_id, requester_thumbprint,
            )
            if order is not None:
                return order, None
        return None, None

    def _challenge_domain(self, order, authz_url):
        """Identifier a challenge validates, for the DNS-01 automation.

        A single-domain order is unambiguous. For a multi-SAN order the first
        domain is *not* necessarily the one this challenge belongs to (taking it
        created the TXT record under the wrong name), so the authz is fetched
        and its own identifier used.
        """
        domains = order.domains_list or []
        if len(domains) == 1:
            return self._strip_wildcard(domains[0])
        if authz_url:
            resp = self._post_with_account(authz_url, "")
            if resp.status_code == 200:
                value = (resp.json().get('identifier') or {}).get('value', '')
                if value:
                    return self._strip_wildcard(value)
        raise ProxyChallengeIdentifierError(
            f"Cannot determine which identifier of order {order.id} this "
            "challenge validates"
        )

    @staticmethod
    def _upstream_authz_url_from_link(upstream_link):
        """Raw upstream authz URL from a challenge response Link rel="up" header.

        requests joins repeated Link headers with ', ', so every link-value is
        scanned and only rel="up" is accepted — RFC 8288 allows the relation to
        be quoted or bare. There is deliberately no "first link wins" fallback:
        rel="index" (the directory) is commonly listed first, and picking it
        would bind the challenge to an unrelated resource.
        """
        if not upstream_link:
            return None
        for match in _LINK_VALUE_RE.finditer(upstream_link):
            url, params = match.group(1), match.group(2) or ''
            if _LINK_REL_UP_RE.search(params):
                return url
        return None

    def _get_authz_link(self, upstream_link):
        """Extract and rewrite authz Link header from upstream response"""
        authz_url = self._upstream_authz_url_from_link(upstream_link)
        if authz_url:
            return f'<{self.base_url}/authz/{self._proxy_id(authz_url)}>;rel="up"'
        return None

    def _make_worker_service(self):
        """Build the service instance a background thread signs through.

        A worker must not reuse this instance: _refresh_account_session() would
        rebind the shared account to the worker's own session, racing both the
        request thread that may still be using it and the sibling threads a
        multi-domain order starts. Only the plain account id crosses the thread
        boundary, so nothing ORM-bound is shared. Patchable in tests.
        """
        return AcmeProxyService(self.base_url, account_id=self._account_id)

    def _bg_respond_challenge(self, app, chall_url, key_authz, domain, order_id,
                              authz_url=None):
        """Background task for DNS setup and upstream validation trigger.

        Upstream signing runs on a thread-owned service instance built by
        _make_worker_service(); this instance's ORM state is never touched here.
        """
        import hashlib
        from api.v2.acme_domains import find_provider_for_domain
        from services.acme.dns_providers import create_provider
        from models import AcmeClientOrder

        with app.app_context():
            try:
                worker = self._make_worker_service()

                # Calculate TXT value
                digest = hashlib.sha256(key_authz.encode()).digest()
                txt_value = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

                # Get fresh order and provider
                order = db.session.get(AcmeClientOrder, order_id)
                provider_info = find_provider_for_domain(domain)
                if not order or not provider_info:
                    logger.error(f"[ACME Proxy BG] Order {order_id} or provider for {domain} not found")
                    return

                provider_model = provider_info['provider']
                credentials = json.loads(provider_model.credentials) if provider_model.credentials else {}
                provider = create_provider(provider_model.provider_type, credentials)

                # Hand the provider the name being validated and let it
                # resolve its own zone, which is what the ACME client path
                # already does. Guessing the zone here took it away from the
                # providers that can ask their API: a delegated child zone
                # was invisible to them, and the record landed in the parent
                # where the resolver never serves it.
                zone_name = self._strip_wildcard(domain)
                full_record_name = provider.get_acme_challenge_name(domain)

                logger.info(f"[ACME Proxy BG] Creating DNS TXT record for {domain}: {full_record_name}")
                provider.create_txt_record(zone_name, full_record_name, txt_value)

                # Client-side pre-check support (#306/#307): lego/Caddy compute
                # the expected TXT value from THEIR account key, not from the
                # proxy's upstream account, so their propagation check could
                # never see the value published above. The client thumbprints
                # are known: publish their values too (extra TXT records on
                # the same name are ignored by the upstream CA validator).
                for extra_value in self._client_txt_values(
                    order, key_authz, txt_value, authz_url=authz_url
                ):
                    try:
                        provider.create_txt_record(zone_name, full_record_name, extra_value)
                        records = json.loads(order.dns_records_created) if order.dns_records_created else []
                        records.append({
                            'domain': zone_name,
                            'record_name': full_record_name,
                            'value': extra_value,
                            'provider_id': provider_model.id
                        })
                        order.dns_records_created = json.dumps(records)
                        db.session.commit()
                    except Exception as exc:
                        logger.warning(f"[ACME Proxy BG] Client TXT value not published: {exc}")

                # Active DNS self-check instead of fixed sleep.
                timeout = dns_propagation_timeout('acme.client.dns_propagation_timeout')
                acme_log(
                    logger,
                    '[ACME Proxy BG] DNS propagation wait for %s: timeout=%ss, record=%s',
                    domain, timeout, full_record_name,
                )
                if timeout <= 0:
                    logger.info("[ACME Proxy BG] DNS propagation wait skipped (timeout=0)")
                    check = {'ok': True, 'missing': [], 'waited': 0}
                else:
                    check = wait_for_txt(full_record_name, txt_value, timeout)
                if not check['ok']:
                    # Soft-fail: our local resolver may miss the record (split-horizon,
                    # filtered egress DNS) while the CA still sees it. Warn, keep the
                    # TXT record in place, and submit upstream — the CA is authoritative.
                    logger.warning(
                        "[ACME Proxy BG] DNS TXT not visible locally after %ss for %s (%s), "
                        "submitting upstream anyway",
                        timeout, domain, full_record_name,
                    )
                else:
                    logger.info("[ACME Proxy BG] DNS TXT confirmed after %ss for %s", check['waited'], domain)

                # Store record info for cleanup
                records = json.loads(order.dns_records_created) if order.dns_records_created else []
                records.append({
                    'domain': zone_name,
                    'record_name': full_record_name,
                    'value': txt_value,
                    'provider_id': provider_model.id
                })
                order.dns_records_created = json.dumps(records)
                db.session.commit()

                # Trigger upstream validation
                logger.info(f"[ACME Proxy BG] Triggering upstream validation for {domain}")
                payload = {}
                resp = worker._post_with_account(chall_url, payload)

                if resp.status_code != 200:
                    logger.error(f"[ACME Proxy BG] Upstream challenge validation error: {resp.text}")
                else:
                    logger.info(f"[ACME Proxy BG] Upstream challenge validation triggered successfully for {domain}")
                    challenges_data = order.challenges_dict
                    entry = challenges_data.get(chall_url, {})
                    entry['status'] = 'submitted'
                    entry['submitted_at'] = datetime.now().isoformat()
                    challenges_data[chall_url] = entry
                    order.set_challenges_dict(challenges_data)
                    db.session.commit()

            except Exception as e:
                logger.error(f"[ACME Proxy BG] Error in background challenge setup: {e}", exc_info=True)
                db.session.rollback()
            finally:
                db.session.remove()

    @staticmethod
    def _delete_dns_record(provider, zone: str, record_name: str) -> None:
        """Best-effort TXT cleanup helper."""
        try:
            provider.delete_txt_record(zone, record_name)
        except Exception as e:
            logger.warning("Failed to cleanup DNS record %s (%s): %s", record_name, zone, e)

    def _bg_cleanup_dns_records(self, app, records):
        """Background task: delete DNS-01 TXT records after cert issuance (#218)."""
        from models import DnsProvider
        from services.acme.dns_providers import create_provider

        with app.app_context():
            try:
                for record in records:
                    try:
                        provider_model = db.session.get(DnsProvider, record['provider_id'])
                        if not provider_model:
                            continue
                        credentials = json.loads(provider_model.credentials) if provider_model.credentials else {}
                        provider = create_provider(provider_model.provider_type, credentials)
                        logger.info(f"[ACME Proxy] Cleaning up DNS record: {record['record_name']} in zone {record['domain']}")
                        self._delete_dns_record(provider, record['domain'], record['record_name'])
                    except Exception as e:
                        logger.warning(f"[ACME Proxy] Failed to cleanup DNS record: {e}")
            finally:
                db.session.remove()

    def _persist_certificate_url(self, order_url: str, cert_url: str):
        """Persist the upstream certificate URL on the local proxy order row.

        Lets _find_order_for_certificate resolve the order with an indexed
        query instead of a live upstream scan (#219).
        """
        from models import AcmeClientOrder
        try:
            row = AcmeClientOrder.query.filter_by(
                is_proxy_order=True, upstream_order_url=order_url
            ).first()
            if row and row.certificate_url != cert_url:
                row.certificate_url = cert_url
                db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.warning(f"ACME proxy: failed to persist certificate URL: {exc}")

    def _find_order_for_certificate(self, cert_url: str, requester_account_id=None,
                                    requester_thumbprint=None):
        """Match a proxy order to the upstream certificate download URL.

        Fast path: indexed lookup on the persisted certificate_url. The upstream
        scan only remains as a fallback for orders that predate the persistence
        (#219) and skips rows that already carry a URL. Each candidate costs one
        signed upstream POST, so the scan is capped and restricted to rows the
        requester could own (plus legacy rows with no owner binding, which
        _verify_order_ownership also serves) — an unrestricted scan let any
        caller make the proxy POST for every other tenant's order and burn the
        upstream account's rate limit.
        """
        from models import AcmeClientOrder

        order = AcmeClientOrder.query.filter_by(
            is_proxy_order=True, certificate_url=cert_url
        ).first()
        if order:
            return order

        owner_filters = [
            and_(
                AcmeClientOrder.account_id.is_(None),
                AcmeClientOrder.client_jwk_thumbprint.is_(None),
            )
        ]
        if requester_account_id:
            owner_filters.append(AcmeClientOrder.account_id == requester_account_id)
        if requester_thumbprint:
            owner_filters.append(
                AcmeClientOrder.client_jwk_thumbprint == requester_thumbprint
            )

        pending_orders = AcmeClientOrder.query.filter(
            AcmeClientOrder.is_proxy_order.is_(True),
            AcmeClientOrder.status == 'pending',
            AcmeClientOrder.certificate_url.is_(None),
            or_(*owner_filters),
        ).order_by(AcmeClientOrder.id.desc()).limit(_CERT_SCAN_LIMIT).all()

        for order in pending_orders:
            if not order.upstream_order_url:
                continue
            try:
                resp = self._post_with_account(order.upstream_order_url, "")
                if resp.status_code != 200:
                    continue
                upstream_cert = resp.json().get('certificate')
                if upstream_cert == cert_url:
                    return order
            except Exception as exc:
                logger.warning(
                    "ACME proxy: failed to resolve order for cert URL: %s", exc
                )
        return None

    def _get_account_thumbprint(self):
        """Get JWK thumbprint of our upstream account key"""
        return self._jwk_thumbprint()

    def _build_eab(self, kid, hmac_key_b64, account_url):
        """Build External Account Binding JWS (RFC 8555 §7.3.4)"""
        import hashlib
        import hmac as hmac_mod

        # Decode HMAC key (base64url-encoded)
        hmac_key_padded = hmac_key_b64 + '=' * (4 - len(hmac_key_b64) % 4)
        hmac_key = base64.urlsafe_b64decode(hmac_key_padded)

        # Protected header for EAB
        protected = {
            "alg": "HS256",
            "kid": kid,
            "url": account_url
        }
        protected_b64 = base64.urlsafe_b64encode(
            json.dumps(protected).encode()
        ).rstrip(b'=').decode()

        # Payload is the account key JWK
        jwk_json = json.dumps(self.account_jwk, separators=(',', ':'), sort_keys=True)
        payload_b64 = base64.urlsafe_b64encode(jwk_json.encode()).rstrip(b'=').decode()

        # HMAC-SHA256 signature
        signing_input = f"{protected_b64}.{payload_b64}".encode()
        sig = hmac_mod.new(hmac_key, signing_input, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()

        return {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig_b64
        }

    def _rewrite_order_urls(self, order, order_id_b64, order_url):
        """Point an upstream order representation back at the proxy.

        Shared by get_order/finalize_order, and caches the upstream finalize URL
        on the way through so finalize_order can skip its extra round-trip.
        """
        if order.get('finalize'):
            _cache_put(_finalize_url_cache, order_url, order['finalize'])
        order['finalize'] = f"{self.base_url}/order/{order_id_b64}/finalize"

        if 'certificate' in order:
            cert_url = order['certificate']
            self._persist_certificate_url(order_url, cert_url)
            order['certificate'] = f"{self.base_url}/cert/{self._proxy_id(cert_url)}"

        if 'authorizations' in order:
            order['authorizations'] = [
                f"{self.base_url}/authz/{self._proxy_id(authz_url)}"
                for authz_url in order['authorizations']
            ]
        return order

    def get_order(self, order_id_b64, requester_account_id=None,
                  requester_thumbprint=None):
        """Get order status (POST-as-GET) — the order must be a tracked proxy
        order owned by the requester (#260)."""
        from models import AcmeClientOrder

        order_url = self._decode_proxy_id(order_id_b64)

        local_order = AcmeClientOrder.query.filter_by(
            upstream_order_url=order_url, is_proxy_order=True
        ).first()
        if local_order is None:
            raise ProxyResourceNotFoundError("Order not found")
        self._verify_order_ownership(
            local_order, requester_account_id, requester_thumbprint,
        )

        resp = self._post_with_account(order_url, "")
        if resp.status_code != 200:
            raise Exception(f"Upstream error: {resp.text}")

        return self._rewrite_order_urls(resp.json(), order_id_b64, order_url)

    def finalize_order(self, order_id_b64, csr_pem, requester_account_id=None,
                       requester_thumbprint=None):
        """Proxy finalize.

        The order must be a tracked proxy order owned by the requester —
        same binding as every other order-scoped proxy endpoint (#260):
        account_id and/or client_jwk_thumbprint recorded at new-order must
        match the verified requester identity, failing closed when an
        owner-bound order gets no derivable identity at all.
        """
        from models import AcmeClientOrder

        order_url = self._decode_proxy_id(order_id_b64)

        local_order = AcmeClientOrder.query.filter_by(
            upstream_order_url=order_url, is_proxy_order=True
        ).first()
        if local_order is None:
            raise ProxyResourceNotFoundError("Order not found")
        self._verify_order_ownership(
            local_order, requester_account_id, requester_thumbprint,
        )

        # ACME expects the CSR as base64url-encoded DER inside the JSON payload;
        # the API handler decoded the client's JWS into PEM, so convert back.
        from cryptography import x509
        csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        csr_b64 = base64.urlsafe_b64encode(csr_der).rstrip(b'=').decode()

        payload = {"csr": csr_b64}

        # The finalize URL is authoritative from the upstream order object. It
        # is captured at new-order (and on every get_order), so the extra
        # POST-as-GET only runs on a cache miss.
        finalize_url = _cache_get(
            _finalize_url_cache, order_url, _FINALIZE_CACHE_TTL_SEC
        )
        if not finalize_url:
            order_resp = self._post_with_account(order_url, "")
            if order_resp.status_code != 200:
                raise RuntimeError(
                    f"Upstream order fetch failed: HTTP {order_resp.status_code}"
                )
            try:
                finalize_url = order_resp.json()['finalize']
            except (ValueError, KeyError) as exc:
                raise RuntimeError(
                    "Upstream order response carries no finalize URL"
                ) from exc
            _cache_put(_finalize_url_cache, order_url, finalize_url)

        # Call finalize
        resp = self._post_with_account(finalize_url, payload)

        if resp.status_code != 200:
            raise Exception(f"Upstream finalize error: {resp.text}")

        return self._rewrite_order_urls(resp.json(), order_id_b64, order_url)

    def get_certificate(self, cert_id_b64, requester_account_id=None,
                        requester_thumbprint=None):
        """Proxy certificate download with DNS cleanup and storage.

        The certificate must belong to a tracked proxy order owned by the
        requester (#260); the order is resolved before the upstream fetch.
        """
        from models import AcmeClientOrder, Certificate
        from services.acme.dns_providers import create_provider
        from services.cert_service import CertificateService

        cert_url = self._decode_proxy_id(cert_id_b64)

        order = self._find_order_for_certificate(
            cert_url,
            requester_account_id=requester_account_id,
            requester_thumbprint=requester_thumbprint,
        )
        if order is None:
            raise ProxyResourceNotFoundError("Certificate not found")
        self._verify_order_ownership(
            order, requester_account_id, requester_thumbprint,
            resource='Certificate',
        )

        resp = self._post_with_account(cert_url, "")

        # Never forward the upstream Link header: its rel="alternate" entries
        # point directly at the real CA and can only be authenticated with our
        # upstream account key — a downstream client following them signs with
        # a proxy-scoped kid and gets rejected by the CA (#220). The preferred
        # chain is already resolved server-side below and served in the body.
        link_header = None

        # Body served to the client — replaced by the selected chain below on 200.
        response_body = resp.content

        if resp.status_code == 200:
            # Certificate obtained successfully
            from services.acme.acme_chain_selection import select_acme_certificate_chain

            def _fetch_alternate(url: str) -> str:
                alt_resp = self._post_with_account(url, "")
                if alt_resp.status_code != 200:
                    raise RuntimeError(
                        f'Alternate chain fetch failed: HTTP {alt_resp.status_code}'
                    )
                content = alt_resp.content
                return content.decode('utf-8') if isinstance(content, bytes) else content

            preferred = None
            if self.account:
                preferred = (self.account.preferred_chain or '').strip() or None

            cert_pem = select_acme_certificate_chain(
                resp.content.decode('utf-8') if isinstance(resp.content, bytes) else resp.content,
                resp.headers,
                preferred,
                _fetch_alternate,
            )
            # Serve the selected (preferred) chain to the client, not just store it.
            response_body = cert_pem

            stored_cert = None
            # Store the certificate in the database
            try:
                # The response usually contains full chain, extract first cert
                certs = cert_pem.split('-----END CERTIFICATE-----')
                if certs and certs[0].strip():
                    first_cert = certs[0].strip() + '\n-----END CERTIFICATE-----\n'
                    # Build chain from remaining certs
                    remaining = [c.strip() + '\n-----END CERTIFICATE-----\n' for c in certs[1:] if c.strip()]
                    chain = ''.join(remaining) if remaining else None

                    # Extract CN for description
                    from cryptography import x509
                    cert_obj = x509.load_pem_x509_certificate(first_cert.encode(), default_backend())
                    cn = cert_obj.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                    descr = cn[0].value if cn else "External ACME Certificate"

                    # self.account may be a stub without a label in some
                    # legacy/proxy paths — stay defensive here.
                    logger.info(
                        "[ACME Proxy] Storing certificate issued by %s: %s",
                        getattr(self.account, 'label', None) or 'External ACME CA',
                        descr,
                    )

                    stored_cert = CertificateService.import_certificate(
                        descr=descr,
                        cert_pem=first_cert,
                        chain_pem=chain,
                        source='acme_client',
                        username='acme_proxy'
                    )
                    logger.info(f"[ACME Proxy] Certificate stored with ID: {stored_cert.id}")
            except Exception as e:
                # Log but don't fail - cert was obtained
                logger.error(f"[ACME Proxy] Error storing certificate: {e}")

            # Link certificate to order (resolved before the upstream fetch);
            # DNS cleanup runs in the background so the client is not blocked
            # on DNS-provider API latency (#218).
            records_to_cleanup = []
            try:
                # Link certificate to order
                if stored_cert:
                    order.certificate_id = stored_cert.id

                # Snapshot DNS records, then commit the order state before
                # any provider round-trip.
                if order.dns_records_created:
                    records_to_cleanup = json.loads(order.dns_records_created)

                order.status = 'valid'
                order.dns_records_created = None  # Cleanup dispatched below
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Failed to update order status: {e}")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed during certificate cleanup: {e}")

            # Opt-in: purge certificates superseded by this renewal (#240)
            if stored_cert:
                try:
                    self._prune_replaced_certificates(order, stored_cert.id)
                except Exception as e:
                    logger.error(f"[ACME Proxy] Prune of replaced certificates failed: {e}")

            if records_to_cleanup:
                app = current_app._get_current_object()

                thread = threading.Thread(
                    target=self._bg_cleanup_dns_records,
                    args=(app, records_to_cleanup)
                )
                thread.name = "ACMEProxy-DNS-Cleanup"
                thread.daemon = True
                thread.start()

        # Cert response is PEM stream usually
        return response_body, resp.headers.get('Content-Type', 'application/pem-certificate-chain'), link_header
