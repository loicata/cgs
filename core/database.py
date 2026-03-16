"""SQLite models via Peewee."""
import os, logging
from datetime import datetime
from peewee import (
    SqliteDatabase, Model, AutoField, CharField, IntegerField, BigIntegerField,
    FloatField, DateTimeField, TextField, BooleanField,
)

logger = logging.getLogger("cgs.db")
db = SqliteDatabase(None)

class _B(Model):
    class Meta:
        database = db

class Host(_B):
    id = AutoField()
    ip = CharField(unique=True, index=True)
    mac = CharField(null=True, index=True)
    hostname = CharField(null=True)
    vendor = CharField(null=True)
    os_hint = CharField(null=True)
    status = CharField(default="up")
    risk_score = IntegerField(default=0)
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)
    open_ports_cache = TextField(default="")
    notes = TextField(null=True)

class Port(_B):
    id = AutoField()
    host_ip = CharField(index=True)
    port = IntegerField()
    proto = CharField(default="tcp")
    state = CharField(default="open")
    service = CharField(null=True)
    banner = TextField(null=True)
    first_seen = DateTimeField(default=datetime.now)
    last_seen = DateTimeField(default=datetime.now)
    class Meta:
        indexes = ((("host_ip", "port", "proto"), True),)

class Flow(_B):
    id = AutoField()
    ts = DateTimeField(default=datetime.now, index=True)
    src_ip = CharField(index=True)
    src_port = IntegerField(null=True)
    dst_ip = CharField(index=True)
    dst_port = IntegerField(null=True)
    proto = CharField(default="TCP")
    packets = IntegerField(default=1)
    bytes_total = BigIntegerField(default=0)
    flags = CharField(null=True)

class Alert(_B):
    id = AutoField()
    ts = DateTimeField(default=datetime.now, index=True)
    severity = IntegerField(default=3, index=True)
    source = CharField(index=True)
    category = CharField(null=True)
    title = CharField()
    detail = TextField(null=True)
    src_ip = CharField(null=True)
    dst_ip = CharField(null=True)
    ioc = CharField(null=True)
    ack = BooleanField(default=False)

class BaselineStat(_B):
    id = AutoField()
    key = CharField(unique=True, index=True)
    value = FloatField(default=0)
    std_dev = FloatField(default=0)
    samples = IntegerField(default=0)
    updated = DateTimeField(default=datetime.now)

class DnsLog(_B):
    id = AutoField()
    ts = DateTimeField(default=datetime.now, index=True)
    src_ip = CharField(index=True)
    query = CharField(index=True)
    qtype = IntegerField(null=True)
    entropy = FloatField(null=True)
    suspicious = BooleanField(default=False)

class WebUser(_B):
    id = AutoField()
    username = CharField(unique=True, index=True)
    password_hash = CharField()
    role = CharField(default="user")  # "admin" or "user"
    email = CharField(null=True)
    ip = CharField(null=True, index=True)
    mac = CharField(null=True, index=True)
    hostname = CharField(null=True)
    must_change_password = BooleanField(default=False)
    totp_secret = CharField(null=True)
    company = CharField(null=True)     # optional company name (used in compliance reports)
    active = BooleanField(default=True)
    created_at = DateTimeField(default=datetime.now)
    last_login = DateTimeField(null=True)

class ComplianceAnswer(_B):
    """Stores self-assessed compliance answers (declarative controls)."""
    id = AutoField()
    control_id = CharField(index=True)          # e.g. "ORG-01"
    answer = CharField(default="no")            # "yes", "no", "partial"
    detail = TextField(null=True)               # free text (evidence, date, notes)
    answered_by = CharField(null=True)          # username
    updated_at = DateTimeField(default=datetime.now)

    class Meta:
        indexes = ((("control_id",), True),)    # one answer per control

# ── GRC Models ──

class Risk(_B):
    id = AutoField()
    title = CharField()
    description = TextField(null=True)
    category = CharField(default="operational")
    likelihood = IntegerField(default=3)
    impact = IntegerField(default=3)
    risk_score = IntegerField(default=9)
    owner = CharField(null=True)
    status = CharField(default="open")
    treatment = CharField(default="mitigate")
    treatment_plan = TextField(null=True)
    review_date = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.now)
    updated_at = DateTimeField(default=datetime.now)
    created_by = CharField(null=True)

class Asset(_B):
    id = AutoField()
    asset_type = CharField(default="server")
    name = CharField()
    owner = CharField(null=True)
    criticality = IntegerField(default=3)
    classification = CharField(default="internal")
    location = CharField(null=True)
    description = TextField(null=True)
    dependencies = TextField(null=True)
    host_id = IntegerField(null=True, index=True)
    created_at = DateTimeField(default=datetime.now)
    updated_at = DateTimeField(default=datetime.now)
    created_by = CharField(null=True)

class Evidence(_B):
    id = AutoField()
    control_id = CharField(index=True)
    filename = CharField()
    stored_name = CharField()
    file_size = IntegerField(default=0)
    mime_type = CharField(null=True)
    description = TextField(null=True)
    uploaded_by = CharField(null=True)
    uploaded_at = DateTimeField(default=datetime.now)

class ComplianceSnapshot(_B):
    id = AutoField()
    ts = DateTimeField(default=datetime.now, index=True)
    score = IntegerField()
    auto_score = IntegerField()
    decl_score = IntegerField(null=True)
    risk_level = CharField()
    passed = IntegerField()
    failed = IntegerField()
    unanswered = IntegerField(default=0)
    categories_json = TextField(default="{}")
    frameworks_json = TextField(null=True)

class Policy(_B):
    id = AutoField()
    title = CharField()
    content = TextField(null=True)
    version = CharField(default="1.0")
    status = CharField(default="draft")
    author = CharField(null=True)
    approver = CharField(null=True)
    approved_date = DateTimeField(null=True)
    next_review_date = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.now)
    updated_at = DateTimeField(default=datetime.now)

class PolicyAck(_B):
    id = AutoField()
    policy_id = IntegerField(index=True)
    username = CharField(index=True)
    acked_at = DateTimeField(default=datetime.now)
    class Meta:
        indexes = ((("policy_id", "username"), True),)

class Audit(_B):
    id = AutoField()
    title = CharField()
    scope = TextField(null=True)
    auditor = CharField(null=True)
    scheduled_date = DateTimeField(null=True)
    status = CharField(default="planned")
    created_at = DateTimeField(default=datetime.now)
    updated_at = DateTimeField(default=datetime.now)
    created_by = CharField(null=True)

class AuditFinding(_B):
    id = AutoField()
    audit_id = IntegerField(index=True)
    severity = CharField(default="medium")
    description = TextField()
    remediation_plan = TextField(null=True)
    responsible = CharField(null=True)
    due_date = DateTimeField(null=True)
    status = CharField(default="open")
    created_at = DateTimeField(default=datetime.now)
    updated_at = DateTimeField(default=datetime.now)

class RiskControlMap(_B):
    id = AutoField()
    risk_id = IntegerField(index=True)
    control_id = CharField(index=True)
    notes = TextField(null=True)
    created_at = DateTimeField(default=datetime.now)
    class Meta:
        indexes = ((("risk_id", "control_id"), True),)

class Vendor(_B):
    id = AutoField()
    name = CharField()
    service = CharField(null=True)
    criticality = IntegerField(default=3)
    last_assessed = DateTimeField(null=True)
    risk_level = CharField(default="medium")
    contact = CharField(null=True)
    notes = TextField(null=True)
    created_at = DateTimeField(default=datetime.now)
    updated_at = DateTimeField(default=datetime.now)
    created_by = CharField(null=True)

class VendorQuestion(_B):
    id = AutoField()
    vendor_id = IntegerField(index=True)
    question = CharField()
    answer = CharField(default="unanswered")
    notes = TextField(null=True)
    updated_at = DateTimeField(default=datetime.now)

_ALL_TABLES = [
    Host, Port, Flow, Alert, BaselineStat, DnsLog, WebUser, ComplianceAnswer,
    Risk, Asset, Evidence, ComplianceSnapshot, Policy, PolicyAck,
    Audit, AuditFinding, RiskControlMap, Vendor, VendorQuestion,
]

def migrate_db():
    """Add missing columns/tables for upgrades. Safe to run multiple times."""
    missing_columns = []

    # Check each table exists and add missing columns
    for model in _ALL_TABLES:
        table_name = model._meta.table_name
        try:
            model.select().limit(1).execute()
        except Exception:
            # Table doesn't exist, create it
            db.create_tables([model])
            continue

        # Check for missing columns
        existing = {col.name for col in db.get_columns(table_name)}
        for field_name, field_obj in model._meta.fields.items():
            col_name = field_obj.column_name
            if col_name not in existing:
                missing_columns.append((table_name, col_name, field_obj))

    # Backup DB before making schema changes
    if missing_columns:
        import shutil
        db_path = db.database
        if db_path and os.path.exists(db_path):
            backup_path = db_path + f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(db_path, backup_path)
            logger.info("DB backup: %s", backup_path)

    # Apply migrations
    for table_name, col_name, field_obj in missing_columns:
        try:
            from playhouse.migrate import SqliteMigrator, migrate as pw_migrate
            migrator = SqliteMigrator(db)
            pw_migrate(migrator.add_column(table_name, col_name, field_obj))
            logger.info("Migration: added column %s.%s", table_name, col_name)
        except Exception as e:
            logger.warning("Migration failed for %s.%s: %s", table_name, col_name, e)


def init_db(data_dir: str):
    path = os.path.join(data_dir, "cgs.db")
    db.init(path, pragmas={"journal_mode": "wal", "cache_size": -64_000,
                           "synchronous": 1, "foreign_keys": 1})
    db.connect()
    db.create_tables(_ALL_TABLES)
    migrate_db()
    logger.info("DB: %s", path)

def is_setup_complete() -> bool:
    """Check if at least one admin user exists."""
    try:
        return WebUser.select().where(WebUser.role == "admin", WebUser.active == True).count() > 0
    except Exception:
        return False
