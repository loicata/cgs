"""SQLite models via Peewee."""
import os, logging
from datetime import datetime
from peewee import (
    SqliteDatabase, Model, AutoField, CharField, IntegerField, BigIntegerField,
    FloatField, DateTimeField, TextField, BooleanField,
)

logger = logging.getLogger("cyberguard.db")
db = SqliteDatabase(None)

def init_db(data_dir: str):
    path = os.path.join(data_dir, "cyberguard.db")
    db.init(path, pragmas={"journal_mode": "wal", "cache_size": -64_000,
                           "synchronous": 1, "foreign_keys": 1})
    db.connect()
    db.create_tables([Host, Port, Flow, Alert, BaselineStat, DnsLog])
    logger.info("BDD : %s", path)

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
