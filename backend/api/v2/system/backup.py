"""
System Backup Operations
"""

from services.backup import storage
from services.backup.decrypt_mixin import BackupDecryptionError
from . import bp
from flask import request, send_file
from auth.unified import require_auth
from utils.response import success_response, error_response
from services.audit_service import AuditService
from services.backup_service import (
    BackupService,
    BackupExportError,
    BackupPasswordError,
    BackupSchemaError,
    BackupValidationError,
    ContainerError,
)
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4
import logging
import os
import tempfile
import werkzeug.utils

from utils.file_validation import validate_upload, BACKUP_EXTENSIONS

logger = logging.getLogger(__name__)

_ALLOWED_BACKUP_EXTENSIONS = (".ucmbkp", ".json.enc")
_MAX_BACKUP_UPLOAD_SIZE = 100 * 1024 * 1024
_MAX_BULK_DELETE_FILES = 1000


def _backup_dir() -> str:
    """Return the configured backup directory."""
    try:
        from config.settings import Config
        return str(Config.BACKUP_DIR)
    except Exception:
        return "/opt/ucm/data/backups"


def _backup_root() -> Path:
    """Return the resolved backup directory path."""
    return Path(_backup_dir()).resolve()


def _human_size(size_bytes: int) -> str:
    """Format a byte count for API responses."""
    if size_bytes > 1024 * 1024:
        return f"{size_bytes / 1024 / 1024:.1f} MB"
    if size_bytes > 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def _is_backup_filename(filename: str) -> bool:
    """Return whether a filename has an allowed backup extension."""
    return bool(filename) and filename.endswith(_ALLOWED_BACKUP_EXTENSIONS)


def _resolve_backup_file(raw_filename: str) -> tuple[Path, str]:
    """
    Validate and resolve a backup filename safely.

    Rejects traversal attempts, filenames changed by secure_filename(), unsupported
    extensions, symlinks, and paths outside of the configured backup directory.
    """
    if not isinstance(raw_filename, str):
        raise ValueError("Invalid backup filename")

    filename = werkzeug.utils.secure_filename(raw_filename)

    # Do not silently transform a potentially malicious requested path into a
    # different valid filename.
    if not filename or filename != raw_filename:
        raise ValueError("Invalid backup filename")

    if not _is_backup_filename(filename):
        raise ValueError("Invalid backup filename")

    backup_dir = _backup_root()
    candidate = backup_dir / filename

    # Backups must be normal files managed by this service, not symlinks.
    if candidate.is_symlink():
        raise PermissionError("Symlinked backup files are not permitted")

    try:
        resolved = candidate.resolve()
        if not resolved.is_relative_to(backup_dir):
            raise PermissionError("Backup path is outside the backup directory")
    except (ValueError, RuntimeError) as exc:
        raise ValueError("Invalid backup path") from exc

    return resolved, filename


def _request_restart_after_restore():
    """Ask the service to restart, the one way this project restarts.

    A restore replaces the certificate authorities, their keys and the
    identities; the running workers hold the previous ones in memory.
    """
    try:
        from utils.service_manager import restart_service
        ok = restart_service()
        return bool(ok), "restart requested"
    except Exception as exc:
        logger.warning("Restore: could not request a restart: %s", exc)
        return False, "restart the service manually"


def _safe_audit_log(**kwargs) -> None:
    """
    Record audit events without converting an already-completed operation into
    an API failure when the audit subsystem is temporarily unavailable.
    """
    try:
        AuditService.log_action(**kwargs)
    except Exception:
        logger.exception("Operation completed but audit logging failed")


def _new_backup_filename() -> str:
    """Generate a collision-resistant backup filename."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    return f"ucm_backup_{timestamp}_{uuid4().hex[:12]}.ucmbkp"


@bp.route("/api/v2/system/backup", methods=["POST"])
@bp.route("/api/v2/system/backup/create", methods=["POST"])
@require_auth(["admin:system"])
def create_backup():
    """Create an encrypted backup and save it to the configured backup directory."""
    try:
        data = request.get_json(silent=True) or {}
        password = data.get("password")

        if not password:
            return error_response("Password required for encryption", 400)

        service = BackupService()
        try:
            # The rules live in the service; the route no longer keeps its own
            # partial copy of them, which said nothing about the others (#346)
            service._validate_password(password)
        except BackupPasswordError as exc:
            return error_response(str(exc), 400)

        backup_bytes = service.create_backup(password)

        backup_dir = _backup_root()

        # UUID collisions are exceptionally unlikely, but retry safely if one occurs.
        filepath = None
        filename = None
        for _ in range(5):
            filename = _new_backup_filename()
            try:
                filepath = storage.publish_validated_archive(
                    backup_dir, filename, backup_bytes)
                break
            except FileExistsError:
                continue

        if filepath is None or filename is None:
            logger.error("Could not allocate a unique backup filename")
            return error_response("Failed to save backup", 500)

        _safe_audit_log(
            action="system_backup",
            resource_type="system",
            resource_name=filename,
            details=f"Created backup: {filename}",
            success=True,
        )

        return success_response(
            message="Backup created successfully",
            data={
                "filename": filename,
                "size": _human_size(len(backup_bytes)),
                "size_bytes": len(backup_bytes),
                "download_url": f"/api/v2/system/backup/{filename}/download",
            },
        )

    except BackupPasswordError as exc:
        return error_response(str(exc), 400)
    except BackupExportError as exc:
        logger.error("Backup aborted: %s", exc)
        return error_response(f"Backup aborted: {exc}", 500)
    except BackupValidationError as exc:
        logger.error("Backup written but not validated: %s", exc)
        return error_response(f"Backup could not be validated: {exc}", 500)
    except ValueError as exc:
        logger.warning("Backup validation error: %s", exc)
        return error_response("Invalid backup parameters", 400)
    except Exception:
        logger.exception("Backup failed")
        return error_response("Backup failed", 500)


@bp.route("/api/v2/system/backups", methods=["GET"])
@bp.route("/api/v2/system/backup/list", methods=["GET"])
@require_auth(["admin:system"])
def list_backups():
    """
    List available backups with pagination, search, sorting, summary, and disk use.

    Query parameters:
      - page
      - per_page (maximum 100)
      - search
      - sort: created_desc, created_asc, size_desc, size_asc,
              name_asc, name_desc
    """
    try:
        backup_dir = _backup_root()
        files = []

        if backup_dir.exists() and backup_dir.is_dir():
            for entry in backup_dir.iterdir():
                if (
                    not _is_backup_filename(entry.name)
                    or entry.is_symlink()
                    or not entry.is_file()
                ):
                    continue

                try:
                    stat = entry.stat()
                except OSError:
                    continue

                files.append(
                    {
                        "filename": entry.name,
                        "size": _human_size(stat.st_size),
                        "size_bytes": stat.st_size,
                        "mtime": stat.st_mtime,
                        "created_at": datetime.fromtimestamp(
                            stat.st_mtime,
                            tz=timezone.utc,
                        ).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    }
                )

        total_all = len(files)
        total_size_all = sum(item["size_bytes"] for item in files)

        search = (request.args.get("search") or "").strip().lower()
        if search:
            files = [
                item
                for item in files
                if search in item["filename"].lower()
            ]

        filtered_total = len(files)
        filtered_total_size = sum(item["size_bytes"] for item in files)

        sort = request.args.get("sort", "created_desc")
        sorters = {
            "created_desc": (lambda item: item["mtime"], True),
            "created_asc": (lambda item: item["mtime"], False),
            "size_desc": (lambda item: item["size_bytes"], True),
            "size_asc": (lambda item: item["size_bytes"], False),
            "name_asc": (lambda item: item["filename"].lower(), False),
            "name_desc": (lambda item: item["filename"].lower(), True),
        }
        key, reverse = sorters.get(sort, sorters["created_desc"])
        files.sort(key=key, reverse=reverse)

        try:
            page = max(1, int(request.args.get("page", 1)))
        except (ValueError, TypeError):
            page = 1

        try:
            per_page = min(100, max(1, int(request.args.get("per_page", 20))))
        except (ValueError, TypeError):
            per_page = 20

        start = (page - 1) * per_page
        page_items = files[start:start + per_page]

        for item in page_items:
            item.pop("mtime", None)

        disk = {}
        try:
            import shutil

            disk_usage = shutil.disk_usage(
                backup_dir if backup_dir.exists() else backup_dir.parent
            )
            disk = {
                "disk_total_bytes": disk_usage.total,
                "disk_free_bytes": disk_usage.free,
                "disk_free": _human_size(disk_usage.free),
                "disk_used_pct": (
                    round(disk_usage.used / disk_usage.total * 100, 1)
                    if disk_usage.total
                    else None
                ),
            }
        except OSError:
            logger.warning("Unable to determine backup filesystem disk usage")

        meta = {
            "total": filtered_total,
            "total_all": total_all,
            "total_size_bytes": filtered_total_size,
            "total_size": _human_size(filtered_total_size),
            "total_size_all_bytes": total_size_all,
            "total_size_all": _human_size(total_size_all),
            "page": page,
            "per_page": per_page,
            "pages": max(1, (filtered_total + per_page - 1) // per_page),
            **disk,
        }

        return success_response(data={"items": page_items, "meta": meta})

    except Exception:
        logger.exception("Failed to list backups")
        return error_response("Failed to list backups", 500)


@bp.route("/api/v2/system/backup/<filename>/download", methods=["GET"])
@require_auth(["admin:system"])
def download_backup(filename):
    """Download an existing backup file."""
    try:
        backup_file, safe_filename = _resolve_backup_file(filename)
    except ValueError:
        return error_response("Invalid backup filename", 400)
    except PermissionError:
        return error_response("Access denied", 403)

    if not backup_file.is_file() or backup_file.is_symlink():
        return error_response("Backup file not found", 404)

    return send_file(
        backup_file,
        as_attachment=True,
        download_name=safe_filename,
        mimetype="application/octet-stream",
        conditional=True,
    )


@bp.route("/api/v2/system/backup/<filename>", methods=["DELETE"])
@require_auth(["admin:system"])
def delete_backup(filename):
    """Delete one backup file."""
    try:
        backup_file, safe_filename = _resolve_backup_file(filename)
    except ValueError:
        return error_response("Invalid backup filename", 400)
    except PermissionError:
        return error_response("Access denied", 403)

    try:
        if not backup_file.is_file() or backup_file.is_symlink():
            return error_response("Backup file not found", 404)

        backup_file.unlink()

        _safe_audit_log(
            action="backup_delete",
            resource_type="system",
            resource_name=safe_filename,
            details=f"Deleted backup: {safe_filename}",
            success=True,
        )

        return success_response(message="Backup deleted successfully")

    except OSError:
        logger.exception("Failed to delete backup: %s", safe_filename)
        return error_response("Failed to delete backup", 500)


@bp.route("/api/v2/system/backups/bulk-delete", methods=["POST"])
@require_auth(["admin:system"])
def bulk_delete_backups():
    """Delete several backups at once. Request body: `{"filenames": [...]}`."""
    data = request.get_json(silent=True) or {}
    names = data.get("filenames")

    if not isinstance(names, list) or not names:
        return error_response("filenames must be a non-empty list", 400)

    if len(names) > _MAX_BULK_DELETE_FILES:
        return error_response("Too many files in one request", 400)

    deleted = 0
    missing = 0
    invalid = 0
    failed = 0
    processed_names = set()

    for raw_name in names:
        try:
            backup_file, safe_filename = _resolve_backup_file(raw_name)
        except (ValueError, PermissionError):
            invalid += 1
            continue

        # Avoid counting or attempting the same file multiple times.
        if safe_filename in processed_names:
            continue
        processed_names.add(safe_filename)

        try:
            if not backup_file.is_file() or backup_file.is_symlink():
                missing += 1
                continue

            backup_file.unlink()
            deleted += 1

        except FileNotFoundError:
            missing += 1
        except OSError:
            logger.exception("Failed to bulk-delete backup: %s", safe_filename)
            failed += 1

    _safe_audit_log(
        action="backup_delete",
        resource_type="system",
        resource_name=f"{deleted} backup(s)",
        details=(
            f"Bulk-deleted {deleted} backup(s); "
            f"{missing} missing, {invalid} invalid, {failed} failed"
        ),
        success=(failed == 0),
    )

    return success_response(
        data={
            "deleted": deleted,
            "missing": missing,
            "invalid": invalid,
            "failed": failed,
        },
        message=f"Deleted {deleted} backup(s)",
    )


@bp.route("/api/v2/system/backups/run-retention", methods=["POST"])
@require_auth(["admin:system"])
def run_retention_now():
    """Apply the configured backup retention policy immediately."""
    try:
        from services.backup.schedule import run_backup_retention

        removed = run_backup_retention()

    except Exception:
        logger.exception("Run retention failed")
        return error_response("Failed to apply retention", 500)

    _safe_audit_log(
        action="backup_delete",
        resource_type="system",
        resource_name=f"{removed} backup(s)",
        details=f"Applied retention, removed {removed} expired backup(s)",
        success=True,
    )

    return success_response(
        data={"removed": removed},
        message=f"Retention applied — removed {removed} backup(s)",
    )


@bp.route("/api/v2/system/restore", methods=["POST"])
@bp.route("/api/v2/system/backup/restore", methods=["POST"])
@require_auth(["admin:system"])
def restore_backup():
    """Restore system data from an encrypted backup upload."""
    try:
        if "file" not in request.files:
            return error_response("No backup file provided", 400)

        uploaded_file = request.files["file"]
        password = request.form.get("password")

        if not password:
            return error_response("Password required for decryption", 400)

        if len(password) < 12:
            return error_response("Password must be at least 12 characters", 400)

        try:
            backup_bytes, _ = validate_upload(
                uploaded_file,
                BACKUP_EXTENSIONS,
                max_size=_MAX_BACKUP_UPLOAD_SIZE,
            )
        except ValueError as exc:
            logger.warning("Backup upload validation error: %s", exc)
            return error_response("Invalid backup file", 400)

        # A restore replaces the instance with the archive, which is what the
        # documentation has always described; merge is available for the rare
        # case of pulling one archive's rows into a live instance.
        mode = (request.form.get('mode') or 'replace').strip().lower()
        if mode not in ('replace', 'merge'):
            return error_response(
                "mode must be 'replace' (the archive becomes this instance) or "
                "'merge' (the archive is added to it)", 400)

        service = BackupService()
        results = service.restore_backup(backup_bytes, password, mode=mode)

        _safe_audit_log(
            action="system_restore",
            resource_type="system",
            resource_name="Backup Restore",
            details="Restored from backup file",
            success=True,
        )

        # The data is in. Now the consequences: every session from before the
        # restore is void (the identities are the archive's), the caches hold
        # the PKI that was just replaced, and the workers need to come back on
        # the restored state.
        from services.backup.restore.invalidate import invalidate_after_restore
        try:
            results['invalidated'] = invalidate_after_restore()
        except Exception:
            logger.exception("Restore: sessions could not be revoked")
            return error_response(
                "Backup restored, but the sessions opened before it could not "
                "be revoked. Restart UCM before using it.", 500)

        restart_ok, restart_message = _request_restart_after_restore()
        results['restart_requested'] = restart_ok

        not_restored = results.get('sections_not_restored') or []
        message = ("Backup restored successfully. Sign in again"
                   if restart_ok else
                   f"Backup restored successfully. Restart UCM to finish: {restart_message}")
        if not_restored:
            # The archive carries more than this version applies; saying so is
            # the difference between a restore and a restore that looked fine.
            message += (". The archive also holds sections this version does "
                        "not restore: " + ", ".join(not_restored))

        return success_response(
            message=message,
            data=results,
        )

    except BackupDecryptionError:
        logger.warning("Restore refused: the backup could not be decrypted")
        return error_response("Wrong backup password, or the file is not a valid backup", 400)
    except (ContainerError, BackupSchemaError) as exc:
        # These messages are ours, they name what the archive got wrong (an
        # unreadable schema, a KDF profile out of range, a section short of
        # its count) and say nothing about its contents. Answering "invalid
        # restore parameters" left an administrator with an archive from a
        # newer UCM no way to know that was the reason.
        logger.warning("Restore refused: %s", exc)
        return error_response(str(exc), 400)
    except ValueError as exc:
        logger.warning("Restore validation error: %s", exc)
        return error_response("Invalid restore parameters", 400)
    except Exception:
        logger.exception("Restore failed")
        return error_response("Restore failed", 500)