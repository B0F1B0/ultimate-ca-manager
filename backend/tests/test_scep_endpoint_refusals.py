"""A SCEP endpoint that is switched off or misconfigured refuses every
operation, capabilities included, with a status a client can act on."""
import pytest

from models import SystemConfig, db


def _set(key, value):
    row = SystemConfig.query.filter_by(key=key).first()
    if row is None:
        db.session.add(SystemConfig(key=key, value=value))
    else:
        row.value = value
    db.session.commit()


@pytest.fixture
def scep_config(app):
    """Restore the keys a test rewrites."""
    keys = ('scep_enabled', 'scep_ca_id')
    with app.app_context():
        saved = {k: (SystemConfig.query.filter_by(key=k).first() or SystemConfig(key=k, value=None)).value for k in keys}
    yield _set
    with app.app_context():
        for k, v in saved.items():
            row = SystemConfig.query.filter_by(key=k).first()
            if v is None:
                if row:
                    db.session.delete(row)
            else:
                _set(k, v)
        db.session.commit()


@pytest.mark.parametrize("operation", ["GetCACaps", "GetCACert", "GetNextCACert", ""])
def test_switched_off_scep_refuses_every_get(app, client, scep_config, operation):
    with app.app_context():
        scep_config('scep_enabled', 'false')
    r = client.get(f"/scep/pkiclient.exe?operation={operation}")
    assert r.status_code == 503, r.get_data(as_text=True)
    assert "SCEP is disabled" in r.get_data(as_text=True)


def test_switched_off_scep_refuses_enrollment(app, client, scep_config):
    with app.app_context():
        scep_config('scep_enabled', 'false')
    r = client.post("/scep/pkiclient.exe?operation=PKIOperation", data=b"\x30\x00",
                    content_type="application/x-pki-message")
    assert r.status_code == 503


@pytest.mark.parametrize("operation", ["GetCACaps", "GetCACert"])
def test_unknown_profile_is_not_found(client, operation):
    r = client.get(f"/scep/no-such-profile/pkiclient.exe?operation={operation}")
    assert r.status_code == 404
    assert "no-such-profile" in r.get_data(as_text=True)


@pytest.mark.parametrize("operation", ["GetCACaps", "GetCACert"])
def test_endpoint_without_a_ca_is_unavailable_not_broken(app, client, scep_config, operation):
    with app.app_context():
        scep_config('scep_enabled', 'true')
        scep_config('scep_ca_id', '')
    r = client.get(f"/scep/pkiclient.exe?operation={operation}")
    assert r.status_code == 503
    assert "No CA configured" in r.get_data(as_text=True)
