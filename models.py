"""
models.py
Pi Intrusion Testing Appliance - Database Models
Team 3 / ITP 258 Sprint 2

Tables:
  scans          - one record per scan run
  hosts          - one record per discovered host
  open_ports     - one record per open port on a host
  traffic_events - notable packets captured by tshark
  reports        - generated text reports tied to a scan
"""

from flask_sqlalchemy import SQLAlchemy
import datetime

db = SQLAlchemy()


class Scan(db.Model):
    __tablename__ = "scans"

    id           = db.Column(db.Integer, primary_key=True)
    target       = db.Column(db.String(64),  nullable=False)
    started_at   = db.Column(db.DateTime,    default=datetime.datetime.utcnow)
    completed_at = db.Column(db.DateTime,    nullable=True)
    status       = db.Column(db.String(16),  default="running")  # running | complete | failed

    hosts         = db.relationship("Host",         backref="scan", lazy=True, cascade="all, delete-orphan")
    traffic_events = db.relationship("TrafficEvent", backref="scan", lazy=True, cascade="all, delete-orphan")
    report        = db.relationship("Report",        backref="scan", lazy=True, uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan {self.id} target={self.target} status={self.status}>"


class Host(db.Model):
    __tablename__ = "hosts"

    id         = db.Column(db.Integer,     primary_key=True)
    scan_id    = db.Column(db.Integer,     db.ForeignKey("scans.id"), nullable=False)
    ip_address = db.Column(db.String(45),  nullable=False)   # supports IPv4 and IPv6
    hostname   = db.Column(db.String(255), nullable=True)

    open_ports = db.relationship("OpenPort", backref="host", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Host {self.ip_address}>"


class OpenPort(db.Model):
    __tablename__ = "open_ports"

    id       = db.Column(db.Integer,    primary_key=True)
    host_id  = db.Column(db.Integer,    db.ForeignKey("hosts.id"), nullable=False)
    port     = db.Column(db.Integer,    nullable=False)
    protocol = db.Column(db.String(8),  default="tcp")
    state    = db.Column(db.String(16), default="open")
    service  = db.Column(db.String(64), nullable=True)
    version  = db.Column(db.String(128),nullable=True)

    def __repr__(self):
        return f"<OpenPort {self.port}/{self.protocol} {self.service}>"


class TrafficEvent(db.Model):
    __tablename__ = "traffic_events"

    id        = db.Column(db.Integer,    primary_key=True)
    scan_id   = db.Column(db.Integer,    db.ForeignKey("scans.id"), nullable=False)
    timestamp = db.Column(db.String(64), nullable=True)
    src_ip    = db.Column(db.String(45), nullable=True)
    dst_ip    = db.Column(db.String(45), nullable=True)
    protocol  = db.Column(db.String(32), nullable=True)
    info      = db.Column(db.Text,       nullable=True)
    severity  = db.Column(db.String(16), default="info")   # info | warning | critical

    def __repr__(self):
        return f"<TrafficEvent {self.protocol} {self.src_ip}->{self.dst_ip} [{self.severity}]>"


class Report(db.Model):
    __tablename__ = "reports"

    id           = db.Column(db.Integer,  primary_key=True)
    scan_id      = db.Column(db.Integer,  db.ForeignKey("scans.id"), nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    content      = db.Column(db.Text,     nullable=True)

    def __repr__(self):
        return f"<Report scan_id={self.scan_id}>"
