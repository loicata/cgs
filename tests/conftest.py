import os, sys, tempfile, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Create app ONCE at module level to avoid Blueprint re-registration
_app = None
_app_initialized = False

def _get_app():
    global _app
    if _app is None:
        from web.app import app
        _app = app
    return _app

@pytest.fixture
def test_db():
    """Create a temporary database for testing."""
    tmpdir = tempfile.mkdtemp()
    from core.database import init_db, db
    # Close any existing connection
    try:
        if not db.is_closed():
            db.close()
    except Exception:  # nosec B110 — test cleanup, safe to ignore
        pass
    init_db(tmpdir)
    yield tmpdir
    try:
        db.close()
    except Exception:  # nosec B110 — test cleanup, safe to ignore
        pass
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

@pytest.fixture
def test_config(test_db):
    """Create a test Config object."""
    from core.config import Config
    import yaml
    cfg_path = os.path.join(test_db, "config.yaml")
    with open(cfg_path, "w") as f:
        yaml.dump({
            "general": {"data_dir": test_db, "log_dir": test_db},
            "network": {"subnets": ["192.168.1.0/24"]},
            "web": {"enabled": True, "port": 9999},
            "defense": {"enabled": True, "auto_block": True},
            "detectors": {"confidence_threshold": 0.6},
        }, f)
    return Config(cfg_path)

@pytest.fixture
def flask_client(test_config, test_db):
    """Create a Flask test client with auth."""
    global _app_initialized
    from web.app import init_app
    app = _get_app()
    if not _app_initialized:
        init_app(test_config, {})
        _app_initialized = True
    else:
        # Just update shared state without re-registering blueprints
        from web import shared
        shared.config = test_config
        shared.ctx.update({})
    app.config["TESTING"] = True
    # Create admin user
    from core.database import WebUser
    import bcrypt
    pw = bcrypt.hashpw(b"testpassword12345", bcrypt.gensalt()).decode()
    try:
        WebUser.create(username="testadmin", password_hash=pw, role="admin", company="TestCorp")
    except Exception:  # nosec B110 — user may already exist from previous test
        pass
    with app.test_client() as client:
        client.post("/login", data={"username": "testadmin", "password": "testpassword12345"})
        yield client
