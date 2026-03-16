def test_login_required(flask_client):
    """Unauthenticated requests should be rejected."""
    from web.app import app
    with app.test_client() as c:
        # Fresh client without login
        r = c.get("/api/overview")
        assert r.status_code in (401, 503, 302)

def test_setup_flow(test_db, test_config):
    """Setup creates admin user."""
    from core.database import WebUser
    import bcrypt
    # Verify we can create a user directly
    pw = bcrypt.hashpw(b"1234567890123456", bcrypt.gensalt()).decode()
    u = WebUser.create(username="setuptest", password_hash=pw, role="admin")
    assert u.id > 0
    from core.database import is_setup_complete
    assert is_setup_complete()

def test_compliance_api(flask_client):
    r = flask_client.get("/api/compliance")
    assert r.status_code == 200
    data = r.json
    assert "score" in data

def test_grc_risks_crud(flask_client):
    csrf = flask_client.get("/api/csrf-token").json["token"]
    r = flask_client.post("/api/grc/risks", json={"title": "Test Risk", "likelihood": 3, "impact": 4},
                          headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    rid = r.json["id"]
    r = flask_client.get("/api/grc/risks")
    assert r.status_code == 200
    csrf = flask_client.get("/api/csrf-token").json["token"]
    r = flask_client.delete(f"/api/grc/risks/{rid}", headers={"X-CSRF-Token": csrf})
    assert r.json["ok"]

def test_search(flask_client):
    csrf = flask_client.get("/api/csrf-token").json["token"]
    flask_client.post("/api/grc/risks", json={"title": "Ransomware threat"},
                      headers={"X-CSRF-Token": csrf})
    r = flask_client.get("/api/search?q=ransomware")
    assert r.status_code == 200
    assert r.json["total"] > 0

def test_user_management(flask_client):
    csrf = flask_client.get("/api/csrf-token").json["token"]
    r = flask_client.post("/api/admin/users", json={
        "username": "newuser", "password": "1234567890123456", "role": "user"
    }, headers={"X-CSRF-Token": csrf})
    assert r.json["ok"]
