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
from sqlalchemy.types import Boolean, Date, DateTime, LargeBinary

from models import db

from ..export_generic import REFERENCE_SUFFIX, load_model
from ..manifest import SECTIONS
from .plan import RestorePlan, RestoreValidationError

logger = logging.getLogger(__name__)


def apply_section(section_name: str, rows: List[Dict[str, Any]],
                  plan: RestorePlan) -> int:
    """Create or update every row of a section. Returns the number applied.

    Raises rather than skipping: a row this version cannot apply is a restore
    that would be announced as complete while missing part of the archive.
    """
    section = SECTIONS[section_name]
    model = load_model(section)
    mapper = sa_inspect(model)

    columns = {column.key: column for column in mapper.columns}
    attribute_of = {}
    for prop in mapper.column_attrs:
        for column in prop.columns:
            attribute_of[column.key] = prop.key

    primary = [column.key for column in mapper.primary_key]
    if len(primary) != 1:
        raise RestoreValidationError(
            f"Section '{section_name}' has a composite primary key; this "
            "version cannot apply it")

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
            # Through the property: it re-encrypts with this installation's key
            setattr(instance, name, value)
            continue

        setattr(instance, attribute_of.get(name, name),
                _coerce(value, column, f"{section_name}.{name}"))


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
    except (ValueError, TypeError) as exc:
        raise RestoreValidationError(
            f"Invalid backup: {where} does not hold a value this column can "
            f"take ({value!r})") from exc
    return value
