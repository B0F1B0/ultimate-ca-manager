"""Making a restore a replacement rather than a merge.

The wiki has always said a restore *replaces* the instance, and it did not:
every restorer upserted what the archive held and left everything else alone.
Restoring after a compromise therefore kept the administrator account, the API
key or the client certificate that was added after the snapshot — the very
rows the restore was meant to remove.

What is removed is deliberately narrow: only sections the archive actually
carries, only rows that can be identified, and never a section the archive
does not mention at all (an archive taken without the optional histories must
not wipe them).
"""
import logging
from typing import Any, Dict, List, Set, Tuple

from sqlalchemy import inspect as sa_inspect

from models import db

from ..export_generic import load_model
from ..manifest import SECTIONS
from .plan import RestorePlan, _identity_key, _normalise

logger = logging.getLogger(__name__)

# Rows that exist for the instance itself rather than for its data: removing
# them would lock the operator out of the server they are restoring.
PROTECTED = {
    'users': lambda row: False,          # handled by the caller's own guard
}


def deletion_order(section_names: Set[str]) -> List[str]:
    """Sections ordered so that a row is removed before what it points at."""
    remaining = set(section_names)
    ordered: List[str] = []
    while remaining:
        # A section can go once nothing left points at it
        free = [name for name in remaining
                if not any(target in remaining
                           for other in remaining
                           for column, target in SECTIONS[other].references.items()
                           if other != name and target == name)]
        if not free:
            # A cycle: order within it cannot be decided, so take the rest as
            # they come and let the database complain if it must.
            ordered.extend(sorted(remaining))
            break
        for name in sorted(free):
            ordered.append(name)
            remaining.discard(name)
    return ordered


def rows_to_remove(section_name: str, archived_rows: List[Dict[str, Any]],
                   plan: RestorePlan) -> List[Any]:
    """Primary keys of the rows here that the archive does not carry."""
    section = SECTIONS[section_name]
    if section.identity == ('id',):
        return []          # singleton configuration: nothing to prune

    archived = {_identity_key(row, section.identity) for row in archived_rows}
    present = plan.target_ids.get(section_name) or {}
    return [target_id for key, target_id in present.items() if key not in archived]


def replace_sections(backup_data: Dict[str, Any], plan: RestorePlan,
                     sections: Set[str], *, keep: Dict[str, Set[Any]] = None
                     ) -> Dict[str, int]:
    """Remove, from the sections the archive carries, what it does not hold.

    Runs inside the restore's transaction, so a failure here undoes the whole
    restore rather than leaving an instance with rows deleted and nothing put
    back.
    """
    keep = keep or {}
    removed: Dict[str, int] = {}

    for section_name in deletion_order(sections):
        archived_rows = backup_data.get(section_name)
        if archived_rows is None or not isinstance(archived_rows, list):
            continue          # not carried by this archive: not ours to prune

        doomed = [target_id for target_id in rows_to_remove(section_name, archived_rows, plan)
                  if target_id not in keep.get(section_name, set())]
        if not doomed:
            continue

        model = load_model(SECTIONS[section_name])
        mapper = sa_inspect(model)
        primary = list(mapper.primary_key)[0]
        count = model.query.filter(primary.in_(doomed)).delete(
            synchronize_session=False)
        db.session.flush()
        removed[section_name] = count
        logger.info("Restore: removed %d row(s) from '%s' that the archive "
                    "does not carry", count, section_name)

    return removed
