import os, sys, tempfile, threading, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Prevent daemon thread accumulation during tests ──
# Modules like RateLimiter, ClientNotificationQueue, ExtendedDetector etc.
# spawn daemon background threads (GC loops, watchers) in __init__.
# When hundreds of test instances are created, 100+ threads accumulate,
# saturating the GIL and causing the test suite to hang.
#
# Fix: monkey-patch Thread.__init__ to neuter known background daemon threads
# so they return immediately when started.

_original_thread_init = threading.Thread.__init__

_NOOP_THREAD_NAMES = frozenset({
    "rate-limiter-gc", "client-queue-gc", "rules-watch",
    "inc-timeout", "defense-gc", "defense-verify",
    "hardening-gc", "killchain-gc", "sniffer",
    "sniffer-analyze", "sniffer-flush", "threat-feed-refresh",
    "safety-monitor", "event-processor",
})


def _patched_thread_init(self, *args, **kwargs):
    _original_thread_init(self, *args, **kwargs)
    if self.daemon and self.name in _NOOP_THREAD_NAMES:
        self._target = lambda *a, **kw: None


threading.Thread.__init__ = _patched_thread_init


_exit_code = 0


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    """Record exit status for forced exit in unconfigure."""
    global _exit_code
    _exit_code = exitstatus


def pytest_unconfigure(config):
    """Force process exit to prevent any residual daemon threads from hanging."""
    os._exit(_exit_code)

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
