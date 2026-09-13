"""Applying a section, from the same manifest the export was written from.

The old restore set a hand-picked subset of fields, and only on rows it
decided to create: restoring over an existing certificate left its subject,
serial, validity and SANs as they were, so a restore could leave an instance
that matched neither the archive nor its previous state. Here every column the
archive carries is applied, to a row that already exists exactly as to a row
being created, and the references are the ones the plan resolved rather than
the source's numeric ids.

Secrets go back through the model's property, not the column: the property is
what re-encrypts them with *this* installation's key, which is what makes an
archive restorable somewhere else at all.
"""
import base64
import logging
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.types import (
    Boolean,
    Date,
    DateTime,
    Integer,
    LargeBinary,
    Numeric,
)

from models import db

from ..export_generic import REFERENCE_SUFFIX, load_model
from ..manifest import SECTIONS
from .plan import RestorePlan, RestoreValidationError

logger = logging.getLogger(__name__)


# Column objects and mapped attribute names per model, built once: a restore
# walks thousands of rows and the mapper does not change between them.
_MAPPING_CACHE: Dict[Any, Any] = {}


def _mapping_of(model):
    """(column by name, mapped attribute name by column name) for a model."""
    cached = _MAPPING_CACHE.get(model)
    if cached is None:
        mapper = sa_inspect(model)
        columns = {column.key: column for column in mapper.columns}
        attribute_of = {}
        for prop in mapper.column_attrs:
            for column in prop.columns:
                attribute_of[column.key] = prop.key
        cached = (columns, attribute_of)
        _MAPPING_CACHE[model] = cached
    return cached


def apply_columns(instance, section_name: str, row: Dict[str, Any],
                  plan: RestorePlan) -> None:
    """Put every column the archive carries for this row onto `instance`.

    This is the whole of "restoring a row", and it is deliberately the same
    call for a row being created and for one that already exists: the restore
    used to set a hand-picked subset of fields on an existing certificate or
    CA, so its subject, serial, SANs, template or CRL cadence stayed at
    whatever the target happened to hold.

    The columns the manifest marks `handled` are left out: a dedicated
    restorer owns them because it is the one holding the archive's master key
    (the PEMs and the private key). Everything else comes from here.
    """
    section = SECTIONS[section_name]
    columns, attribute_of = _mapping_of(type(instance))
    _apply_row(section_name, section, instance, row, columns, attribute_of, plan)


def apply_section(section_name: str, rows: List[Dict[str, Any]],
                  plan: RestorePlan) -> int:
    """Create or update every row of a section. Returns the number applied.

    Raises rather than skipping: a row this version cannot apply is a restore
    that would be announced as complete while missing part of the archive.
    """
    section = SECTIONS[section_name]
    model = load_model(section)
    mapper = sa_inspect(model)
    columns, attribute_of = _mapping_of(model)

    primary = [column.key for column in mapper.primary_key]
    if len(primary) != 1:
        raise RestoreValidationError(
            f"Section '{section_name}' has a composite primary key; this "
            "version cannot apply it")

    # The plan was built before anything was written, which is the point: no
    # row is created until what the restore will do is decided. But a section
    # can point at a row this same restore has just created a few sections
    # earlier, and against the original index that reference resolved to
    # nothing. Where the column requires a value the insert then failed and
    # took the whole restore with it -- a membership, a role permission, a
    # WebAuthn credential, a deployment binding, a template pin, a key
    # recovery request: six sections that made a restore onto a fresh
    # installation impossible.
    #
    # Only the sections this one points at are rebuilt, and only once per
    # section rather than once per row: re-indexing the whole archive for
    # every row would turn a restore into a walk over the database.
    if section.references:
        db.session.flush()
        plan.refresh(sorted(set(section.references.values())))

    applied = 0
    for row in rows:
        target_id = plan.existing_id(section_name, row)
        instance = db.session.get(model, target_id) if target_id is not None else None
        if instance is None:
            instance = model()
            db.session.add(instance)

        _apply_row(section_name, section, instance, row, columns, attribute_of, plan)
        applied += 1

    db.session.flush()
    return applied


def _apply_row(section_name, section, instance, row, columns, attribute_of, plan):
    for name, value in row.items():
        if name.startswith('_') or name.endswith(REFERENCE_SUFFIX):
            continue          # internal marker, or the identity of a reference
        if name in section.handled:
            continue          # the dedicated restorer owns this column
        if name == 'id':
            continue          # the target keeps its own key
        column = columns.get(name)
        if column is None:
            continue          # a column this version does not have

        if name in section.references:
            setattr(instance, attribute_of.get(name, name),
                    plan.resolve(section_name, row, name))
            continue

        if name in section.secrets:
            # Assigned by its manifest name, which is the model's own
            # attribute: where that is a property over a private column the
            # property re-encrypts with this installation's key, and where it
            # is a plain column the column is what the application reads
            # directly (`pyotp.TOTP(user.totp_secret)`, `json.loads(
            # provider.config)`), so the archive's value is what belongs in
            # it. Encrypting those would hand the application a ciphertext it
            # never decrypts: a restored account with MFA that cannot be
            # verified any more.
            setattr(instance, name, value)
            continue

        setattr(instance, attribute_of.get(name, name),
                _coerce(value, column, f"{section_name}.{name}"))


# The widest integer a database column holds: PostgreSQL's bigint, and the
# ceiling SQLite stores as an INTEGER. Anything past it is not a value some
# backend would take and another would not, it is not a value at all.
_INTEGER_LIMIT = 2 ** 63 - 1


def _coerce(value: Any, column, where: str) -> Any:
    """Turn an archived value back into what the column holds."""
    if value is None:
        return None

    kind = column.type
    try:
        if isinstance(kind, LargeBinary) and isinstance(value, str):
            return base64.b64decode(value)
        if isinstance(kind, (DateTime, Date)) and isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is not None:
                parsed = parsed.replace(tzinfo=None)
            return parsed.date() if isinstance(kind, Date) and not isinstance(kind, DateTime) else parsed
        if isinstance(kind, Boolean) and not isinstance(value, bool):
            return bool(value)
        if isinstance(kind, (Integer, Numeric)) and isinstance(value, str):
            # Left alone, "twenty-two" reached SQLite, which stores it, and
            # PostgreSQL, which refuses it: the same archive restored or
            # failed depending on the backend underneath.
            return int(value) if isinstance(kind, Integer) else float(value)
        if isinstance(kind, Integer) and isinstance(value, int):
            # A number no database column can hold. Caught here, where the
            # section and the column can still be named, rather than as an
            # OverflowError from the driver halfway through the transaction.
            if not -_INTEGER_LIMIT <= value <= _INTEGER_LIMIT:
                raise RestoreValidationError(
                    f"Invalid backup: {where} is out of range for this "
                    "column")
    except RestoreValidationError:
        raise
    except (ValueError, TypeError, OverflowError) as exc:
        raise RestoreValidationError(
            f"Invalid backup: {where} does not hold a value this column can "
            f"take ({value!r})") from exc
    return value


def relink_references(backup_data: Dict[str, Any], plan: RestorePlan) -> Dict[str, int]:
    """Point every reference at the row it names, now that all rows exist.

    Sections are applied in an order that cannot satisfy everything at once: a
    certificate authority is restored before the HSM key it uses, so the first
    pass had nothing to resolve its link against and left it empty. Rather
    than order the sections by hand and hope, the references are resolved a
    second time against the database as the restore has just left it.
    """
    plan.refresh()
    relinked: Dict[str, int] = {}

    for section_name, rows in backup_data.items():
        section = SECTIONS.get(section_name)
        if section is None or not section.references or not isinstance(rows, list):
            continue

        model = load_model(section)
        mapper = sa_inspect(model)
        attribute_of = {}
        for prop in mapper.column_attrs:
            for column in prop.columns:
                attribute_of[column.key] = prop.key

        changed = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            target_id = plan.existing_id(section_name, row)
            if target_id is None:
                continue
            instance = db.session.get(model, target_id)
            if instance is None:
                continue
            for column in section.references:
                if column not in row:
                    continue
                resolved = plan.resolve(section_name, row, column)
                attribute = attribute_of.get(column, column)
                if getattr(instance, attribute, None) != resolved:
                    setattr(instance, attribute, resolved)
                    changed += 1
        if changed:
            relinked[section_name] = changed

    db.session.flush()
    return relinked
