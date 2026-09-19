"""Deploy hooks service (#299).

Certificates bound to deploy targets are pushed over SFTP on issuance and
renewal (and on demand), then the target's fixed reload command runs over SSH.
Deliveries go through a durable queue drained by a scheduler task with
exponential backoff — the same model as webhook deliveries: the issuing
request is never blocked on SSH.
"""
import base64
import json
import logging
import posixpath
from datetime import timedelta

from models import db, Certificate, DeployTarget, DeployBinding, DeployDelivery
from security.encryption import encrypt_text, decrypt_text
from utils.datetime_utils import utc_now
from utils.export_options import json_boolean
from utils.key_codec import load_pem_bytes
from services.deploy import ssh as deploy_ssh
from services.deploy.ssh import DeploySSHError

logger = logging.getLogger(__name__)

DEPLOY_EVENTS = ('certificate.issued', 'certificate.renewed')

# File modes on the target: the key is operator-readable only.
MODE_PUBLIC = 0o644
MODE_PRIVATE = 0o600


def _safe_commit(context: str) -> bool:
    """Commit, or roll back and say so.

    It used to swallow the failure and return nothing, so a caller that
    committed the delivery and then recorded it announced a success for a
    record that had just been rolled back: the delivery read as still pending
    for a certificate already on the remote host, and the next pass pushed it
    again.
    """
    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        logger.error(f"Deploy commit failed ({context}): {e}")
        return False


class DeployService:

    DEFAULT_MAX_ATTEMPTS = 5
    _BACKOFF_BASE_SECONDS = 60
    _BACKOFF_CAP_SECONDS = 3600
    _CLAIM_LEASE_SECONDS = 180  # longer than connect+push+reload worst case

    # ---------------------------------------------------------------- files

    @staticmethod
    def resolve_files(binding: DeployBinding, certificate: Certificate):
        """Build [(path, content_bytes, mode)] for a binding. Raises ValueError
        when the binding asks for material the certificate does not have."""
        if not certificate.crt:
            raise ValueError("Certificate has no certificate data to deploy")

        pem_data = base64.b64decode(certificate.crt).decode('utf-8')
        blocks = DeployService._split_pem(pem_data)
        if not blocks:
            raise ValueError("Certificate PEM could not be parsed")
        leaf_pem = blocks[0]

        files = []
        if binding.cert_path:
            files.append((binding.cert_path, leaf_pem.encode(), MODE_PUBLIC))
        if binding.key_path:
            if not certificate.prv:
                raise ValueError(
                    "Binding pushes the private key but UCM does not hold one "
                    "for this certificate (protocol-enrolled?)"
                )
            key_pem = load_pem_bytes(
                certificate.prv, context=f"certificate {certificate.id} deploy")
            files.append((binding.key_path, key_pem, MODE_PRIVATE))
        if binding.fullchain_path:
            chain_pem = DeployService._chain_pem(
                certificate, pem_data, include_root=bool(binding.include_root))
            files.append((binding.fullchain_path, (leaf_pem + chain_pem).encode(), MODE_PUBLIC))
        if not files:
            raise ValueError("Binding has no destination path configured")
        return files

    @staticmethod
    def _split_pem(pem_data: str):
        blocks, current, inside = [], [], False
        for line in pem_data.splitlines():
            if '-----BEGIN CERTIFICATE-----' in line:
                inside, current = True, [line]
            elif '-----END CERTIFICATE-----' in line and inside:
                current.append(line)
                blocks.append('\n'.join(current) + '\n')
                inside = False
            elif inside:
                current.append(line)
        return blocks

    @staticmethod
    def _chain_pem(certificate: Certificate, cert_pem: str,
                   include_root: bool = False) -> str:
        """Issuing chain (excluding the leaf), reusing the export chain walker."""
        from cryptography.hazmat.primitives import serialization
        from api.v2.certificates.export import _build_ca_chain
        try:
            chain = _build_ca_chain(
                certificate, cert_pem.encode(), include_root=include_root)
        except Exception as e:
            logger.warning(f"Deploy: chain build failed for cert {certificate.id}: {e}")
            chain = []
        return ''.join(
            c.public_bytes(serialization.Encoding.PEM).decode() for c in chain)

    # ------------------------------------------------------------- transport

    @staticmethod
    def execute_delivery(delivery: DeployDelivery) -> bool:
        """Perform one push+reload. Returns True when the push happened and
        was recorded.

        The delivery and target rows are updated in place and committed here,
        before the audit entry that describes the push is written: that entry
        commits this session itself, so leaving the rows to the caller meant
        the audit decided whether a push that had already reached the remote
        host was recorded as having happened.

        Only the paths that reach the remote host commit. The three early
        returns above mark the delivery failed and hand it back to the caller
        to commit, as they always did: nothing has left this process yet, so
        there is no record that has to outlive the request.
        """
        now = utc_now()
        binding = db.session.get(DeployBinding, delivery.binding_id)
        if not binding or not binding.enabled:
            delivery.status = DeployDelivery.STATUS_FAILED
            delivery.last_error = 'Binding missing or disabled'
            return False
        target = binding.target
        if not target or not target.enabled:
            delivery.status = DeployDelivery.STATUS_FAILED
            delivery.last_error = 'Target missing or disabled'
            return False
        certificate = db.session.get(Certificate, binding.certificate_id)
        if not certificate:
            delivery.status = DeployDelivery.STATUS_FAILED
            delivery.last_error = 'Certificate no longer exists'
            return False

        detail = {}
        try:
            files = DeployService.resolve_files(binding, certificate)
        except ValueError as e:
            DeployService._record_failure(delivery, target, str(e), now, permanent=True)
            return False

        client = None
        try:
            private_key = decrypt_text(target.private_key)
            client, learned = deploy_ssh.open_client(
                target.host, target.port, target.username, private_key, target.host_key)
            if learned:
                target.host_key = learned
                logger.info(f"Deploy target '{target.name}': pinned host key on first connect")
            deploy_ssh.push_files(client, files)
            detail['pushed'] = [path for path, _, _ in files]
            if target.reload_command:
                exit_status, stderr_tail = deploy_ssh.run_command(client, target.reload_command)
                detail['reload_exit'] = exit_status
                if stderr_tail:
                    detail['reload_stderr'] = stderr_tail[:1024]
                if exit_status != 0:
                    raise DeploySSHError(
                        f"Reload command exited {exit_status}"
                        + (f": {stderr_tail[:300]}" if stderr_tail else ''))
        except deploy_ssh.HostKeyMismatch as e:
            DeployService._record_failure(delivery, target, str(e), now, detail=detail)
            return False
        except DeploySSHError as e:
            DeployService._record_failure(delivery, target, str(e), now, detail=detail)
            return False
        except Exception as e:
            logger.error(f"Deploy delivery {delivery.id} unexpected failure: {e}", exc_info=True)
            DeployService._record_failure(delivery, target, 'Internal deploy error', now, detail=detail)
            return False
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass

        delivery.status = DeployDelivery.STATUS_DELIVERED
        delivery.delivered_at = now
        delivery.last_error = None
        delivery.detail = json.dumps(detail)
        target.last_success_at = now
        target.failure_count = 0

        # The file is already on the remote host and the reload has already
        # run. Record that before the audit, because the audit commits this
        # session and rolls all of it back when its own entry cannot be
        # written: the delivery would read as still pending for something
        # that was delivered, and the next pass would push it again.
        recorded = _safe_commit('execute_delivery')

        from services.audit_service import AuditService
        AuditService.log_action(
            action='deploy_push',
            resource_type='deploy_target',
            resource_id=str(target.id),
            resource_name=target.name,
            details=(
                f"Deployed certificate {certificate.descr or certificate.refid} "
                f"to {target.name} ({', '.join(detail.get('pushed', []))})"
                + (f", reload exit {detail.get('reload_exit')}" if 'reload_exit' in detail else '')
                + ('' if recorded else
                   '; the delivery record could not be saved, so this push '
                   'will be attempted again')
            ),
            username=delivery.triggered_by or 'system',
            success=recorded,
        )
        return recorded

    @staticmethod
    def _record_failure(delivery, target, error, now, permanent=False, detail=None):
        delivery.last_error = error
        if detail:
            delivery.detail = json.dumps(detail)
        target.last_failure_at = now
        target.failure_count = (target.failure_count or 0) + 1
        if permanent or delivery.attempts >= (delivery.max_attempts or DeployService.DEFAULT_MAX_ATTEMPTS):
            delivery.status = DeployDelivery.STATUS_FAILED
        else:
            delivery.next_attempt_at = now + timedelta(
                seconds=DeployService._backoff_seconds(delivery.attempts))

        # Same reason as the success path: the audit commits this session, so
        # the failure count and the retry schedule ride on whether its entry
        # can be written. Rolled back, the attempt is forgotten and the same
        # target is retried without backoff.
        recorded = _safe_commit('record_failure')

        from services.audit_service import AuditService
        AuditService.log_action(
            action='deploy_push',
            resource_type='deploy_target',
            resource_id=str(target.id),
            resource_name=target.name,
            details=(f"Deploy attempt {delivery.attempts} failed: {error}"
                     + ('' if recorded else
                        '; the attempt itself could not be saved, so the '
                        'backoff will not hold')),
            username=delivery.triggered_by or 'system',
            success=False,
        )

    @staticmethod
    def _backoff_seconds(attempts: int) -> int:
        return min(DeployService._BACKOFF_BASE_SECONDS * (2 ** max(attempts - 1, 0)),
                   DeployService._BACKOFF_CAP_SECONDS)

    # ----------------------------------------------------------------- queue

    @staticmethod
    def enqueue_for_event(event_type: str, payload: dict, ca_refid: str = None, meta: dict = None):
        """Bus subscriber: queue one delivery per enabled binding of the cert."""
        if event_type not in DEPLOY_EVENTS:
            return
        cert_id = ((payload or {}).get('certificate') or {}).get('id')
        if not cert_id:
            return
        try:
            bindings = (DeployBinding.query
                        .filter_by(certificate_id=cert_id, enabled=True)
                        .join(DeployTarget)
                        .filter(DeployTarget.enabled == True)  # noqa: E712
                        .all())
        except Exception as e:
            logger.error(f"Deploy enqueue skipped ({event_type}): {e}")
            return
        if not bindings:
            return

        now = utc_now()
        actor = (meta or {}).get('actor')
        for binding in bindings:
            db.session.add(DeployDelivery(
                binding_id=binding.id,
                event_type=event_type,
                status=DeployDelivery.STATUS_PENDING,
                next_attempt_at=now,
                max_attempts=DeployService.DEFAULT_MAX_ATTEMPTS,
                triggered_by=actor or 'system',
            ))
        # Same rule as the webhook subscriber: this runs synchronously inside
        # the originating request — committing must not expire the caller's
        # ORM instances.
        session = db.session()
        prev_expire = session.expire_on_commit
        try:
            session.expire_on_commit = False
            db.session.commit()
            logger.info(f"Deploy: queued {len(bindings)} delivery(ies) for cert {cert_id} ({event_type})")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to queue deploy deliveries for {event_type}: {e}")
        finally:
            session.expire_on_commit = prev_expire

    @staticmethod
    def process_pending_deliveries(limit: int = 20) -> dict:
        """Scheduler task: run due pending deliveries with backoff."""
        now = utc_now()
        result = {'attempted': 0, 'delivered': 0, 'retry': 0, 'failed': 0}
        try:
            due = (DeployDelivery.query
                   .filter(DeployDelivery.status == DeployDelivery.STATUS_PENDING,
                           DeployDelivery.next_attempt_at <= now)
                   .order_by(DeployDelivery.next_attempt_at.asc())
                   .limit(limit).all())
        except Exception as e:
            logger.error(f"Deploy delivery query failed: {e}")
            return result

        for d in due:
            # Atomic claim — same exactly-once pattern as webhook deliveries.
            from sqlalchemy import update as _sa_update
            claimed = db.session.execute(
                _sa_update(DeployDelivery)
                .where(DeployDelivery.id == d.id,
                       DeployDelivery.status == DeployDelivery.STATUS_PENDING,
                       DeployDelivery.next_attempt_at <= now)
                .values(attempts=(DeployDelivery.attempts + 1),
                        next_attempt_at=now + timedelta(seconds=DeployService._CLAIM_LEASE_SECONDS))
            ).rowcount
            db.session.commit()
            if not claimed:
                continue
            db.session.refresh(d)

            result['attempted'] += 1
            ok = DeployService.execute_delivery(d)
            if ok:
                result['delivered'] += 1
            elif d.status == DeployDelivery.STATUS_FAILED:
                result['failed'] += 1
            else:
                result['retry'] += 1
            _safe_commit('process_pending')
        if result['attempted']:
            logger.info(f"Deploy deliveries processed: {result}")
        return result

    # --------------------------------------------------------------- targets

    @staticmethod
    def validate_target_input(data: dict, partial: bool = False) -> dict:
        """Validate/normalize target fields. Raises ValueError."""
        out = {}
        if not partial or 'name' in data:
            name = str(data.get('name') or '').strip()
            if not name or len(name) > 120:
                raise ValueError('name is required (max 120 chars)')
            out['name'] = name
        if not partial or 'host' in data:
            host = str(data.get('host') or '').strip()
            if not host or len(host) > 255 or any(c.isspace() for c in host):
                raise ValueError('host is required (hostname or IP, max 255 chars)')
            out['host'] = host
        if 'port' in data and data.get('port') not in (None, ''):
            try:
                port = int(data['port'])
            except (TypeError, ValueError):
                raise ValueError('port must be an integer')
            if port < 1 or port > 65535:
                raise ValueError('port must be between 1 and 65535')
            out['port'] = port
        if not partial or 'username' in data:
            username = str(data.get('username') or '').strip()
            if not username or len(username) > 120:
                raise ValueError('username is required (max 120 chars)')
            out['username'] = username
        if 'reload_command' in data:
            cmd = str(data.get('reload_command') or '').strip()
            if len(cmd) > 512:
                raise ValueError('reload_command is too long (max 512 chars)')
            out['reload_command'] = cmd or None
        if 'enabled' in data:
            out['enabled'] = bool(data['enabled'])
        return out

    @staticmethod
    def create_target(data: dict, username: str) -> DeployTarget:
        fields = DeployService.validate_target_input(data)
        provided_key = str(data.get('private_key') or '').strip()
        if provided_key:
            deploy_ssh.load_private_key(provided_key)  # validate before storing
            private_key = provided_key
            public_key = deploy_ssh.public_key_from_private(provided_key)
        else:
            private_key, public_key = deploy_ssh.generate_keypair()

        target = DeployTarget(
            **fields,
            private_key=encrypt_text(private_key),
            public_key=public_key,
            created_by=username,
        )
        db.session.add(target)
        return target

    @staticmethod
    def update_target(target: DeployTarget, data: dict) -> DeployTarget:
        fields = DeployService.validate_target_input(data, partial=True)
        host_changed = ('host' in fields and fields['host'] != target.host) or \
                       ('port' in fields and fields['port'] != target.port)
        for key, value in fields.items():
            setattr(target, key, value)
        provided_key = str(data.get('private_key') or '').strip()
        if provided_key:
            deploy_ssh.load_private_key(provided_key)
            target.private_key = encrypt_text(provided_key)
            target.public_key = deploy_ssh.public_key_from_private(provided_key)
        # A different endpoint presents a different host key — re-pin (TOFU).
        if host_changed or data.get('reset_host_key'):
            target.host_key = None
        return target

    @staticmethod
    def test_target(target: DeployTarget) -> dict:
        """Connect + authenticate + open SFTP without writing anything.
        Pins the host key on a first successful connect."""
        private_key = decrypt_text(target.private_key)
        client, learned = deploy_ssh.open_client(
            target.host, target.port, target.username, private_key, target.host_key)
        try:
            sftp = client.open_sftp()
            sftp.close()
        finally:
            client.close()
        if learned:
            target.host_key = learned
        return {
            'host_key_fingerprint': target.host_key_fingerprint(),
            'host_key_pinned_now': bool(learned),
        }

    # -------------------------------------------------------------- bindings

    @staticmethod
    def validate_binding_paths(data: dict, partial: bool = False) -> dict:
        out = {}
        for field in ('cert_path', 'key_path', 'fullchain_path'):
            if partial and field not in data:
                continue
            value = str(data.get(field) or '').strip()
            if value:
                if not posixpath.isabs(value) or len(value) > 512:
                    raise ValueError(f'{field} must be an absolute path (max 512 chars)')
                if value.endswith('/'):
                    raise ValueError(f'{field} must be a file path, not a directory')
            out[field] = value or None
        if 'enabled' in data:
            out['enabled'] = bool(data['enabled'])
        if 'include_root' in data:
            out['include_root'] = json_boolean(data, 'include_root')
        return out

    @staticmethod
    def ensure_distinct_paths(cert_path, key_path, fullchain_path):
        """Two files pushed to the same path silently overwrite each other —
        the last write wins and the delivery still reports success. Refuse."""
        paths = [posixpath.normpath(p) for p in (cert_path, key_path, fullchain_path) if p]
        if len(paths) != len(set(paths)):
            raise ValueError(
                'cert_path, key_path and fullchain_path must be distinct files')

    @staticmethod
    def enqueue_initial_push(binding: DeployBinding, actor: str = 'system'):
        """Queue the first push right after a binding is created (#299 review
        F-07): a binding can only be attached to an already-issued certificate,
        so the certificate.issued event can never match a fresh binding —
        without this, the first deployment always required a manual push."""
        if not binding.enabled or not binding.target or not binding.target.enabled:
            return None
        delivery = DeployDelivery(
            binding_id=binding.id,
            event_type='initial',
            status=DeployDelivery.STATUS_PENDING,
            next_attempt_at=utc_now(),
            max_attempts=DeployService.DEFAULT_MAX_ATTEMPTS,
            triggered_by=actor,
        )
        db.session.add(delivery)
        return delivery


def _register_bus_subscriber():
    from services.events import event_bus
    if getattr(_register_bus_subscriber, '_done', False):
        return
    for event in DEPLOY_EVENTS:
        event_bus.subscribe(event, DeployService.enqueue_for_event)
    _register_bus_subscriber._done = True
    logger.info("Registered deploy-hook event-bus subscriber")
