"""A restore replaces the instance, which is what the documentation says.

Every restorer used to upsert what the archive held and leave the rest alone,
so restoring after a compromise kept the account, the API key or the client
certificate added after the snapshot. These tests pin what is removed, and
just as importantly what is not.
"""
import pytest

from models import db
from services.backup import manifest
from services.backup.restore.plan import RestorePlan
from services.backup.restore.replace import (
    deletion_order, replace_sections, rows_to_remove,
)


class TestDeletionOrder:
    def test_a_section_goes_before_what_it_points_at(self):
        order = deletion_order(set(manifest.SECTIONS))
        position = {name: index for index, name in enumerate(order)}
        for name, section in manifest.SECTIONS.items():
            for column, target in section.references.items():
                if target in position and name in position:
                    assert position[name] < position[target], (
                        f"{name} would be removed after {target}, which it "
                        "points at")

    def test_every_section_is_ordered_once(self):
        order = deletion_order(set(manifest.SECTIONS))
        assert sorted(order) == sorted(manifest.SECTIONS)


class TestWhatIsRemoved:
    def test_a_row_the_archive_does_not_carry_is_named(self, app):
        from models.group import Group
        with app.app_context():
            kept = Group(name='replace-kept-group')
            extra = Group(name='replace-extra-group')
            db.session.add_all([kept, extra])
            db.session.commit()
            try:
                archived = [{'name': 'replace-kept-group'}]
                plan = RestorePlan.build({'groups': archived})
                doomed = rows_to_remove('groups', archived, plan)
                assert extra.id in doomed
                assert kept.id not in doomed
            finally:
                Group.query.filter(Group.name.in_(
                    ['replace-kept-group', 'replace-extra-group'])).delete(
                    synchronize_session=False)
                db.session.commit()

    def test_a_section_the_archive_does_not_mention_is_untouched(self, app):
        """An archive taken without the optional histories must not wipe them."""
        from models.group import Group
        with app.app_context():
            group = Group(name='replace-untouched-group')
            db.session.add(group)
            db.session.commit()
            try:
                plan = RestorePlan.build({})
                removed = replace_sections({}, plan, {'groups'})
                assert removed == {}
                assert Group.query.filter_by(name='replace-untouched-group').first()
            finally:
                db.session.delete(group)
                db.session.commit()

    def test_rows_named_as_kept_survive(self, app):
        from models.group import Group
        with app.app_context():
            extra = Group(name='replace-protected-group')
            db.session.add(extra)
            db.session.commit()
            try:
                # Everything the target holds except the protected row, so the
                # only candidate for removal is the one named as kept.
                archived = [{'name': group.name} for group in Group.query.all()
                            if group.name != 'replace-protected-group']
                payload = {'groups': archived}
                plan = RestorePlan.build(payload)
                removed = replace_sections(payload, plan, {'groups'},
                                           keep={'groups': {extra.id}})
                assert removed.get('groups', 0) == 0
                assert Group.query.filter_by(name='replace-protected-group').first()
            finally:
                Group.query.filter_by(name='replace-protected-group').delete()
                db.session.commit()

    def test_a_singleton_section_is_never_pruned(self, app):
        with app.app_context():
            plan = RestorePlan.build({'smtp_config': []})
            assert rows_to_remove('smtp_config', [], plan) == []


PASSWORD = 'Correct-Horse-Battery-9'


def _service():
    from services.backup_service import BackupService
    return BackupService()


def _only(*names):
    return {name: name in names for name in manifest.SECTIONS}


class TestARestoreIsAReplacement:
    """What the wiki always promised, and the restore never did."""

    def test_a_row_added_after_the_snapshot_is_removed(self, app):
        from models.group import Group
        with app.app_context():
            before = Group(name='replace-in-archive')
            db.session.add(before)
            db.session.commit()

            blob = _service().create_backup(PASSWORD, include=_only('groups'))

            # Added after the snapshot: exactly what a restore after a
            # compromise is meant to take away.
            after = Group(name='replace-added-after-snapshot')
            db.session.add(after)
            db.session.commit()

            try:
                _service().restore_backup(blob, PASSWORD)
                db.session.expire_all()
                assert Group.query.filter_by(name='replace-in-archive').first()
                assert Group.query.filter_by(
                    name='replace-added-after-snapshot').first() is None
            finally:
                Group.query.filter(Group.name.in_(
                    ['replace-in-archive', 'replace-added-after-snapshot'])).delete(
                    synchronize_session=False)
                db.session.commit()

    def test_merge_mode_keeps_it(self, app):
        from models.group import Group
        with app.app_context():
            db.session.add(Group(name='merge-in-archive'))
            db.session.commit()
            blob = _service().create_backup(PASSWORD, include=_only('groups'))
            db.session.add(Group(name='merge-added-after-snapshot'))
            db.session.commit()

            try:
                _service().restore_backup(blob, PASSWORD, mode='merge')
                db.session.expire_all()
                assert Group.query.filter_by(
                    name='merge-added-after-snapshot').first() is not None
            finally:
                Group.query.filter(Group.name.in_(
                    ['merge-in-archive', 'merge-added-after-snapshot'])).delete(
                    synchronize_session=False)
                db.session.commit()

    def test_a_section_the_archive_left_out_is_untouched(self, app, create_user):
        """An archive of the groups alone must not remove the users."""
        from models import User
        create_user(username='replace_untouched_user', role='operator')
        with app.app_context():
            blob = _service().create_backup(PASSWORD, include=_only('groups'))
            _service().restore_backup(blob, PASSWORD)
            db.session.expire_all()
            assert User.query.filter_by(username='replace_untouched_user').first()

    def test_an_unknown_mode_is_refused_before_anything_happens(self, app):
        from services.backup.errors import BackupSchemaError
        with app.app_context():
            blob = _service().create_backup(PASSWORD, include=_only('groups'))
            with pytest.raises(BackupSchemaError, match='Unknown restore mode'):
                _service().restore_backup(blob, PASSWORD, mode='overwrite')
