"""What the restore decides before it writes anything.

Two questions are answered here, on the archive alone and on the target's
current state, never by writing: is every row of every section something this
version can apply, and which target row does each archived row and each
archived reference correspond to.

The second question is the one the old restore got wrong in the way that
hurts most quietly: it wrote the source's numeric ids into the target, so a
group membership, an API key or a client certificate could land on whichever
user happened to hold that id here.
"""
import base64
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import inspect as sa_inspect

from ..export_generic import REFERENCE_SUFFIX, load_model
from ..manifest import SECTIONS, Section

logger = logging.getLogger(__name__)


class RestoreValidationError(ValueError):
    """The archive holds something this version will not apply.

    Raised before the first write, so the message can say plainly that
    nothing was changed.
    """


# Sections whose payload is a mapping, not a list of rows.
_MAPPING_SECTIONS = {'configuration', 'https_server'}


class RestorePlan:
    """The decisions taken before the first write."""

    def __init__(self):
        self.target_ids: Dict[str, Dict[Tuple, Any]] = {}
        self.rows: Dict[str, List[Dict[str, Any]]] = {}
        self.warnings: List[str] = []

    # -- building ---------------------------------------------------------

    @classmethod
    def build(cls, backup_data: Dict[str, Any]) -> 'RestorePlan':
        plan = cls()
        plan._validate_shape(backup_data)
        plan._index_target_rows(backup_data)
        return plan

    def _validate_shape(self, backup_data: Dict[str, Any]) -> None:
        """Every section is the shape this version applies, row by row."""
        for name, value in backup_data.items():
            if name in ('metadata', 'checksum'):
                continue
            section = SECTIONS.get(name)
            if section is None:
                # Not a section this version knows: reported elsewhere, and
                # not a reason to refuse an archive from a neighbouring
                # version that carries more than we do.
                continue

            if name in _MAPPING_SECTIONS:
                if not isinstance(value, dict):
                    raise RestoreValidationError(
                        f"Invalid backup: section '{name}' should be an object")
                continue

            if not isinstance(value, list):
                raise RestoreValidationError(
                    f"Invalid backup: section '{name}' should be a list of rows")

            for position, row in enumerate(value):
                if not isinstance(row, dict):
                    raise RestoreValidationError(
                        f"Invalid backup: row {position} of section '{name}' is "
                        "not an object")
                self._validate_identity(name, section, row, position)
            self.rows[name] = value

    def _validate_identity(self, name: str, section: Section, row: Dict[str, Any],
                           position: int) -> None:
        """A row with no identity cannot be matched to a row here.

        It is still restorable: it is written as a new row, and nothing can
        point at it. Refusing the whole archive over one such row would make
        an installation carrying rows older than the column that identifies
        them impossible to restore at all.
        """
        if section.identity == ('id',):
            return  # singleton configuration rows
        missing = [field for field in section.identity
                   if row.get(field) in (None, '')]
        if missing:
            self.warnings.append(
                f"row {position} of section '{name}' has no "
                f"{', '.join(missing)}: it will be restored as a new row and "
                "nothing can point at it"
            )

    def _index_target_rows(self, backup_data: Dict[str, Any]) -> None:
        """Map each section's stable identity to the id it has *here*."""
        for name in set(self.rows) | _referenced_sections(backup_data):
            section = SECTIONS.get(name)
            if section is None or name in _MAPPING_SECTIONS:
                continue
            self.target_ids[name] = _index_of(section)

    def refresh(self, section_names=None) -> None:
        """Rebuild the identity indexes from the database as it is now.

        The plan is built before anything is written, so it only knows the
        rows that existed then. Once the restore has created the rows the
        archive carries, a reference pointing at one of them can be resolved,
        which the first pass could not do.
        """
        for name in (section_names or list(self.target_ids)):
            section = SECTIONS.get(name)
            if section is None or name in _MAPPING_SECTIONS:
                continue
            self.target_ids[name] = _index_of(section)

    # -- using ------------------------------------------------------------

    def resolve(self, section_name: str, row: Dict[str, Any],
                column: str) -> Optional[Any]:
        """The target id a reference points at, or None.

        The archive carries both the source id and the identity of the row it
        pointed at; only the identity means anything here.
        """
        section = SECTIONS.get(section_name)
        if section is None:
            return None
        target = section.references.get(column)
        if target is None:
            return row.get(column)

        identity = row.get(f'{column}{REFERENCE_SUFFIX}')
        if not identity:
            # An archive written before references carried identities: the
            # number is all there is, and it means nothing here.
            if row.get(column) is not None:
                self.warnings.append(
                    f"{section_name}.{column} has no identity in this archive; "
                    "the reference was dropped rather than pointed at a "
                    "different row")
            return None

        key = _identity_key(identity, SECTIONS[target].identity)
        return self.target_ids.get(target, {}).get(key)

    def existing_id(self, section_name: str, row: Dict[str, Any]) -> Optional[Any]:
        """The id of the row here that this archived row is, if it exists."""
        section = SECTIONS.get(section_name)
        if section is None:
            return None
        key = _identity_key(row, section.identity)
        return self.target_ids.get(section_name, {}).get(key)


def _identity_key(values: Dict[str, Any], fields: Tuple[str, ...]) -> Tuple:
    return tuple(_normalise(values.get(field)) for field in fields)


def _normalise(value: Any) -> Any:
    if isinstance(value, bytes):
        return base64.b64encode(value).decode()
    if value is None:
        return None
    return str(value)


def _index_of(section: Section) -> Dict[Tuple, Any]:
    model = load_model(section)
    mapper = sa_inspect(model)
    primary = [column.key for column in mapper.primary_key]
    if len(primary) != 1:
        return {}
    index = {}
    for row in model.query.all():
        key = tuple(_normalise(getattr(row, field, None))
                    for field in section.identity)
        index[key] = getattr(row, primary[0])
    return index


def _referenced_sections(backup_data: Dict[str, Any]) -> set:
    """Sections pointed at by a reference in the archive."""
    targets = set()
    for name in backup_data:
        section = SECTIONS.get(name)
        if section:
            targets.update(section.references.values())
    return targets
