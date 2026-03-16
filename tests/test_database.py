def test_create_host(test_db):
    from core.database import Host
    h = Host.create(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", hostname="test-pc")
    assert h.id > 0
    assert Host.get_by_id(h.id).ip == "192.168.1.10"

def test_create_alert(test_db):
    from core.database import Alert
    a = Alert.create(severity=1, source="test", title="Test alert")
    assert a.severity == 1

def test_create_risk(test_db):
    from core.database import Risk
    r = Risk.create(title="Data breach", likelihood=4, impact=5, risk_score=20)
    assert r.risk_score == 20

def test_create_asset(test_db):
    from core.database import Asset
    a = Asset.create(name="Web Server", asset_type="server", criticality=5)
    assert a.criticality == 5

def test_create_policy(test_db):
    from core.database import Policy
    p = Policy.create(title="Security Policy", status="draft", author="admin")
    assert p.status == "draft"

def test_create_vendor(test_db):
    from core.database import Vendor
    v = Vendor.create(name="CloudProvider Inc", criticality=4)
    assert v.name == "CloudProvider Inc"

def test_webuser(test_db):
    from core.database import WebUser
    import bcrypt
    pw = bcrypt.hashpw(b"test1234567890ab", bcrypt.gensalt()).decode()
    u = WebUser.create(username="alice", password_hash=pw, role="user", company="ACME")
    assert u.company == "ACME"
    assert WebUser.get(WebUser.username == "alice").role == "user"

def test_is_setup_complete(test_db):
    from core.database import is_setup_complete, WebUser
    import bcrypt
    assert not is_setup_complete()
    pw = bcrypt.hashpw(b"test1234567890ab", bcrypt.gensalt()).decode()
    WebUser.create(username="admin", password_hash=pw, role="admin")
    assert is_setup_complete()
