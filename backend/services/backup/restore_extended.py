"""
Extended restore methods mixin for BackupService
"""
import uuid
import base64
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import inspect as sa_inspect

from models import db
from config.settings import Config
from utils.datetime_utils import to_naive_utc, utc_now

from .errors import BackupSchemaError
from .export_generic import REFERENCE_SUFFIX, load_model
from .manifest import SECTIONS
from .restore.plan import RestorePlan, RestoreValidationError

logger = logging.getLogger(__name__)


def _missing_support(section_name: str, rows, feature: str) -> None:
    """Say which section an installation without `feature` cannot take.

    The import of an optional model is the one failure here that is not a
    loss: the rows describe a feature this build does not have, so there is
    nothing on this installation for them to be applied to. It used to
    `break` without a word, which is the same outcome without the sentence
    that lets an administrator see it happened.
    """
    logger.warning(
        "Restore: this installation has no %s support; the %d row(s) of "
        "section '%s' in the archive were not applied",
        feature, len(rows), section_name)


def _required(where: str, row: Dict[str, Any], column: str) -> Any:
    """A column the row cannot be written without, or a refusal naming it.

    Raised as a schema error rather than left to the KeyError it used to be:
    the routes return this message to the administrator, and "SSH certificate
    3 names no authority" is what they need, not "Restore failed".
    """
    value = row.get(column)
    if value in (None, ''):
        raise BackupSchemaError(
            f"Invalid backup: {where} has no {column}, which it cannot be "
            "restored without. Nothing has been changed.")
    return value


def _timestamp(where: str, column: str, value: Any,
               required: bool = False) -> Optional[datetime]:
    """The instant the archive recorded, or a refusal.

    A date that could not be parsed used to become None, so an approval
    request came back without the creation date that identifies it and with
    no trace of the value that was dropped.
    """
    if value in (None, ''):
        if required:
            raise RestoreValidationError(
                f"Invalid backup: {where} has no {column}, which is part of "
                "what identifies it; nothing has been changed")
        return None
    if isinstance(value, datetime):
        return to_naive_utc(value)
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except (TypeError, ValueError) as exc:
        raise RestoreValidationError(
            f"Invalid backup: {where} holds {value!r} as its {column}, which "
            "is not a date; nothing has been changed") from exc
    return to_naive_utc(parsed)


def _reference(where: str, section_name: str, row: Dict[str, Any], column: str,
               plan: RestorePlan) -> Optional[Any]:
    """The id this installation holds for the row a reference points at.

    The archive carries the source's numeric id and, beside it, the identity
    of the row it pointed at; only the identity means anything here. The plan
    answers from the index it took before the first write, so a row this very
    restore has just created — the certificate an approval was waiting for,
    the user who asked for it — is looked up again on the session.

    A reference the archive carries and this installation cannot place stops
    the restore: writing the source's number would attach the request to
    whichever row happens to hold it here, and dropping it would turn an
    approved request into one that looks like it is still waiting.
    """
    if row.get(column) is None:
        return None                      # there was no link to carry
    resolved = plan.resolve(section_name, row, column)
    if resolved is None:
        resolved = _target_id(section_name, row, column)
    if resolved is None:
        identity = row.get(f'{column}{REFERENCE_SUFFIX}')
        raise RestoreValidationError(
            f"Invalid backup: {where} points at a "
            f"{SECTIONS[section_name].references[column]} row this "
            f"installation does not have "
            f"({identity or 'the archive carries no identity for it'}); "
            "nothing has been changed")
    return resolved


def _target_id(section_name: str, row: Dict[str, Any], column: str) -> Optional[Any]:
    """The referenced row's id, as the session sees it now.

    The plan's index is a snapshot taken before the restore wrote anything;
    this reads the same identity against the rows the restore has since
    created, which is the difference between a full archive restoring onto a
    fresh installation and one that refuses because its own users are not
    there yet.
    """
    identity = row.get(f'{column}{REFERENCE_SUFFIX}')
    if not identity:
        return None
    section = SECTIONS[SECTIONS[section_name].references[column]]
    values = {field: identity.get(field) for field in section.identity}
    if any(value is None for value in values.values()):
        # An identity this version cannot read in full matches nothing here;
        # looking it up would be a search for a row holding NULL.
        return None
    model = load_model(section)
    found = model.query.filter_by(**values).first()
    if found is None:
        return None
    primary = sa_inspect(model).primary_key
    if len(primary) != 1:
        return None
    return getattr(found, primary[0].key)


def _existing_row(section_name: str, identity: Dict[str, Any]):
    """The row here that an archived row is, by the identity the manifest declares.

    Looked up on the session rather than in the plan's index: for an approval
    request the index holds the source's certificate id and an unparsed date,
    neither of which is what this restore computes, and in both sections it
    was taken before the first write, so a row an earlier row of the same
    archive created would not be in it.

    A row whose identity is empty is no row in particular: it is created
    rather than matched against every other row that has none either. The
    plan has already said so, as a warning, when it read the archive.
    """
    section = SECTIONS[section_name]
    if tuple(identity) != section.identity:
        raise RestoreValidationError(
            f"Section '{section_name}' is identified by "
            f"{', '.join(section.identity)}, not by "
            f"{', '.join(identity)}")
    if all(value in (None, '') for value in identity.values()):
        return None
    return load_model(section).query.filter_by(**identity).first()


class RestoreExtendedMixin:
    def _restore_ssh_cas(self, backup_data: Dict, results: Dict, master_key: bytes) -> None:
        """Restore SSH certificate authorities from backup data.

        A key that cannot be decrypted stops the restore. It used to be a
        warning: the authority was created with an empty private key and
        committed, so the restore reported success and left an SSH CA that
        can sign nothing and that nobody was told about.
        """
        results.setdefault('ssh_cas', 0)
        rows = backup_data.get('ssh_cas', [])
        if not rows:
            return
        try:
            from models.ssh import SSHCertificateAuthority
            from security.encryption import encrypt_private_key
        except ImportError:
            _missing_support('ssh_cas', rows, 'SSH')
            return
        for sca_data in rows:
            refid = sca_data.get('refid')
            existing = SSHCertificateAuthority.query.filter_by(refid=refid).first() if refid else None
            if existing:
                continue
            sca = SSHCertificateAuthority(
                refid=refid or str(uuid.uuid4()),
                descr=sca_data.get('descr', 'Imported SSH CA'),
                ca_type=sca_data.get('ca_type', 'user'),
                key_type=sca_data.get('key_type', 'ed25519'),
                public_key=sca_data.get('public_key', ''),
                private_key='',
                fingerprint=sca_data.get('fingerprint', ''),
                serial_counter=sca_data.get('serial_counter', 0),
                default_ttl=sca_data.get('default_ttl', 86400),
                max_ttl=sca_data.get('max_ttl', 0),
                default_extensions=sca_data.get('default_extensions'),
                allowed_principals=sca_data.get('allowed_principals'),
                comment=sca_data.get('comment'),
                created_by=sca_data.get('created_by'),
                owner_group_id=sca_data.get('owner_group_id'),
            )
            encrypted = sca_data.get('private_key_pem_encrypted')
            prv = sca_data.get('_private_key_plaintext')
            if encrypted:
                try:
                    prv = self._decrypt_private_key(encrypted, master_key)
                except Exception as exc:
                    raise BackupSchemaError(
                        f"Invalid backup: the private key of SSH CA "
                        f"{refid or sca_data.get('descr') or '(unnamed)'} could "
                        "not be decrypted. Restoring it would create an "
                        "authority that can sign nothing; nothing has been "
                        "changed."
                    ) from exc
            if prv:
                sca.private_key = encrypt_private_key(prv)
            db.session.add(sca)
            results['ssh_cas'] += 1

        # One flush for the section, not a commit per row: the restore is one
        # transaction, and a row that cannot be written must take it down
        # rather than become the warning it used to be.
        db.session.flush()

    def _restore_ssh_certificates(self, backup_data: Dict, results: Dict) -> None:
        """Restore SSH certificates from backup data.

        A row that cannot be written is the restore's failure, not a line in
        a log: a missing authority or an unreadable date used to drop the
        certificate and let the restore report the ones that worked.
        """
        results.setdefault('ssh_certificates', 0)
        rows = backup_data.get('ssh_certificates', [])
        if not rows:
            return
        try:
            from models.ssh import SSHCertificate
        except ImportError:
            _missing_support('ssh_certificates', rows, 'SSH')
            return
        for position, sc_data in enumerate(rows):
            where = f"SSH certificate {sc_data.get('refid') or position}"
            refid = sc_data.get('refid')
            if refid and SSHCertificate.query.filter_by(refid=refid).first():
                continue
            sc = SSHCertificate(
                refid=refid or str(uuid.uuid4()),
                descr=sc_data.get('descr'),
                ssh_ca_id=_required(where, sc_data, 'ssh_ca_id'),
                cert_type=sc_data.get('cert_type', 'user'),
                key_id=sc_data.get('key_id', ''),
                public_key=sc_data.get('public_key', ''),
                certificate=sc_data.get('certificate', ''),
                principals=sc_data.get('principals', ''),
                serial=sc_data.get('serial', 0),
                valid_from=_timestamp(where, 'valid_from', sc_data.get('valid_from')) or utc_now(),
                valid_to=_timestamp(where, 'valid_to', sc_data.get('valid_to')) or utc_now(),
                key_type=sc_data.get('key_type', 'ed25519'),
                fingerprint=sc_data.get('fingerprint', ''),
                extensions=sc_data.get('extensions'),
                critical_options=sc_data.get('critical_options'),
                revoked=bool(sc_data.get('revoked', False)),
                revoked_at=_timestamp(where, 'revoked_at', sc_data.get('revoked_at')),
                revoke_reason=sc_data.get('revoke_reason'),
                source=sc_data.get('source', 'web'),
                created_by=sc_data.get('created_by'),
                owner_group_id=sc_data.get('owner_group_id'),
            )
            db.session.add(sc)
            results['ssh_certificates'] += 1

        db.session.flush()

    def _restore_microsoft_cas(self, backup_data: Dict, results: Dict) -> None:
        """Restore Microsoft certificate authorities from backup data.

        A connector the archive carries and this restore cannot write is a
        CA that will not answer on the restored instance; it fails the
        restore instead of disappearing into a warning.
        """
        results.setdefault('microsoft_cas', 0)
        rows = backup_data.get('microsoft_cas', [])
        if not rows:
            return
        try:
            from models.msca import MicrosoftCA
        except ImportError:
            _missing_support('microsoft_cas', rows, 'Microsoft CA')
            return
        for position, msca_data in enumerate(rows):
            where = f"Microsoft CA {msca_data.get('name') or position}"
            if msca_data.get('name') and MicrosoftCA.query.filter_by(
                    name=msca_data['name']).first():
                continue
            msca = MicrosoftCA(
                name=_required(where, msca_data, 'name'),
                server=msca_data.get('server'),
                ca_name=msca_data.get('ca_name'),
                auth_method=msca_data.get('auth_method', 'ntlm'),
                username=msca_data.get('username'),
                password=msca_data.get('password'),
                client_cert_pem=msca_data.get('client_cert_pem'),
                client_key_pem=msca_data.get('client_key_pem'),
                kerberos_principal=msca_data.get('kerberos_principal'),
                kerberos_keytab_path=msca_data.get('kerberos_keytab_path'),
                use_ssl=msca_data.get('use_ssl', True),
                verify_ssl=msca_data.get('verify_ssl', True),
                ca_bundle=msca_data.get('ca_bundle'),
                default_template=msca_data.get('default_template'),
                enabled=msca_data.get('enabled', True),
                created_by=msca_data.get('created_by'),
            )
            db.session.add(msca)
            results['microsoft_cas'] += 1

        db.session.flush()

    def _restore_scan_profiles(self, backup_data: Dict, results: Dict) -> None:
        """Restore scan profiles from backup data.

        A profile the archive carries and this restore drops is a discovery
        scan that will never run again on the restored instance, so it fails
        the restore rather than being logged and passed over.
        """
        results.setdefault('scan_profiles', 0)
        rows = backup_data.get('scan_profiles', [])
        if not rows:
            return
        try:
            from models.discovered_certificate import ScanProfile
        except ImportError:
            _missing_support('scan_profiles', rows, 'certificate discovery')
            return
        for position, sp_data in enumerate(rows):
            where = f"scan profile {sp_data.get('name') or position}"
            if sp_data.get('name') and ScanProfile.query.filter_by(
                    name=sp_data['name']).first():
                continue
            sp = ScanProfile(
                name=_required(where, sp_data, 'name'),
                description=sp_data.get('description'),
                targets=sp_data.get('targets', '[]'),
                ports=sp_data.get('ports', '[443]'),
                schedule_enabled=sp_data.get('schedule_enabled', False),
                schedule_interval_minutes=sp_data.get('schedule_interval_minutes'),
                notify_on_new=sp_data.get('notify_on_new', True),
                notify_on_change=sp_data.get('notify_on_change', True),
                notify_on_expiry=sp_data.get('notify_on_expiry', True),
                timeout=sp_data.get('timeout', 5),
                max_workers=sp_data.get('max_workers', 10),
                resolve_dns=sp_data.get('resolve_dns', True),
            )
            db.session.add(sp)
            results['scan_profiles'] += 1

        db.session.flush()

    def _restore_hsm_keys(self, backup_data: Dict, results: Dict) -> None:
        """Restore HSM keys from backup data.

        A key that does not come back is a CA that cannot sign: the
        authorities are relinked to these rows afterwards, so losing one
        here would restore an HSM-backed CA with no key to reach for. The
        failure stops the restore instead of being logged.
        """
        results.setdefault('hsm_keys', 0)
        rows = backup_data.get('hsm_keys', [])
        if not rows:
            return
        try:
            from models.hsm import HsmKey
        except ImportError:
            _missing_support('hsm_keys', rows, 'HSM')
            return
        for position, k_data in enumerate(rows):
            where = f"HSM key {k_data.get('key_identifier') or position}"
            provider_id = _required(where, k_data, 'provider_id')
            existing = HsmKey.query.filter_by(
                provider_id=provider_id,
                key_identifier=k_data.get('key_identifier'),
            ).first()
            if existing:
                continue
            hk = HsmKey(
                provider_id=provider_id,
                key_identifier=k_data.get('key_identifier'),
                label=k_data.get('label'),
                algorithm=k_data.get('algorithm'),
                key_type=k_data.get('key_type'),
                purpose=k_data.get('purpose'),
                public_key_pem=k_data.get('public_key_pem'),
                is_extractable=k_data.get('is_extractable', False),
                extra_data=k_data.get('extra_data'),
            )
            db.session.add(hk)
            results['hsm_keys'] += 1

        db.session.flush()

    def _restore_approval_requests(self, backup_data: Dict, results: Dict,
                                   plan: RestorePlan) -> None:
        """Restore approval requests, once and with their dates.

        Every row used to be created unconditionally, so restoring the same
        archive twice left two copies of every pending request, each still
        waiting on the same certificate. A request is now the row the
        manifest says it is — the certificate it is about, as that
        certificate is numbered *here*, and the instant it was created — so a
        second restore updates what the first one wrote instead of adding to
        it. The creation date is carried back rather than replaced by the
        moment of the restore, which is also what makes the identity hold.
        """
        from models.policy import ApprovalRequest

        results.setdefault('approval_requests', 0)
        for position, ar_data in enumerate(backup_data.get('approval_requests', [])):
            where = f"approval request {position}"
            created_at = _timestamp(where, 'created_at', ar_data.get('created_at'),
                                    required=True)
            certificate_id = _reference(where, 'approval_requests', ar_data,
                                        'certificate_id', plan)
            requester_id = _reference(where, 'approval_requests', ar_data,
                                      'requester_id', plan)
            if requester_id is None:
                raise RestoreValidationError(
                    f"Invalid backup: {where} names no requester; an approval "
                    "cannot be restored without the user who asked for it")

            request = _existing_row('approval_requests',
                                    {'certificate_id': certificate_id,
                                     'created_at': created_at})
            if request is None:
                request = ApprovalRequest()
                db.session.add(request)

            # Applied to a row that already exists exactly as to a new one:
            # a restore that left half the fields of an existing request as
            # they were would match neither the archive nor what was here.
            request.certificate_id = certificate_id
            request.created_at = created_at
            request.requester_id = requester_id
            request.policy_id = _reference(where, 'approval_requests', ar_data,
                                           'policy_id', plan)
            request.request_type = ar_data.get('request_type', 'certificate')
            request.request_data = ar_data.get('request_data')
            request.requester_comment = ar_data.get('requester_comment')
            request.status = ar_data.get('status', 'pending')
            request.approvals = ar_data.get('approvals', '[]')
            request.required_approvals = ar_data.get('required_approvals', 1)
            request.expires_at = _timestamp(where, 'expires_at',
                                            ar_data.get('expires_at'))
            request.resolved_at = _timestamp(where, 'resolved_at',
                                             ar_data.get('resolved_at'))
            results['approval_requests'] += 1

        db.session.flush()

    def _restore_acme_client_orders(self, backup_data: Dict, results: Dict,
                                    plan: RestorePlan) -> None:
        """Restore the orders UCM placed with an external ACME CA, once.

        An order is the one the CA knows under that URL, so restoring an
        archive twice updates the order it already put back rather than
        placing a second row for the same upstream order.
        """
        from models.acme_models import AcmeClientOrder

        results.setdefault('acme_client_orders', 0)
        for position, o_data in enumerate(backup_data.get('acme_client_orders', [])):
            where = f"ACME client order {position}"
            order = _existing_row('acme_client_orders',
                                  {'order_url': o_data.get('order_url')})
            if order is None:
                order = AcmeClientOrder()
                db.session.add(order)

            order.domains = o_data.get('domains', '[]')
            order.challenge_type = o_data.get('challenge_type', 'dns-01')
            order.environment = o_data.get('environment', 'staging')
            order.key_type = o_data.get('key_type', 'RSA-2048')
            order.status = o_data.get('status', 'pending')
            order.order_url = o_data.get('order_url')
            order.account_url = o_data.get('account_url')
            order.finalize_url = o_data.get('finalize_url')
            order.certificate_url = o_data.get('certificate_url')
            order.challenges_data = o_data.get('challenges_data')
            order.dns_provider_id = _reference(where, 'acme_client_orders', o_data,
                                               'dns_provider_id', plan)
            # The manifest carries no identity for the issued certificate, so
            # there is nothing to resolve it against; the column is left as
            # this restore has always written it.
            order.certificate_id = o_data.get('certificate_id')
            order.renewal_enabled = o_data.get('renewal_enabled', True)
            order.is_proxy_order = o_data.get('is_proxy_order', False)
            order.dns_records_created = o_data.get('dns_records_created')
            order.client_jwk_thumbprint = o_data.get('client_jwk_thumbprint')
            order.upstream_order_url = o_data.get('upstream_order_url')
            order.upstream_authz_urls = o_data.get('upstream_authz_urls')
            order.error_message = o_data.get('error_message')
            results['acme_client_orders'] += 1

        db.session.flush()

    def _restore_https_files(self, backup_data: Dict, results: Dict,
                             staged=None) -> None:
        """Stage the HTTPS server certificate and key.

        Nothing is written where the server reads it until the database
        transaction has committed: the pair used to be written in the middle
        of the restore, so a failure afterwards left the server presenting a
        certificate from an archive that was never applied. Failures are no
        longer swallowed either — a restore that cannot place the key it was
        asked to restore has not restored it.
        """
        https_data = backup_data.get('https_server', {})
        if not https_data:
            return
        if staged is None:
            raise RuntimeError("HTTPS files must be staged, not written directly")

        if https_data.get('cert_pem'):
            staged.stage(Config.HTTPS_CERT_PATH,
                         https_data['cert_pem'].encode(), mode=0o644)
            results['https_server'] += 1
        if https_data.get('key_pem'):
            staged.stage(Config.HTTPS_KEY_PATH,
                         https_data['key_pem'].encode(), mode=0o600)
            results['https_server'] += 1
