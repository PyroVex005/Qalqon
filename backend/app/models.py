from datetime import datetime, timezone
from sqlalchemy import String, Float, DateTime, Text, Integer
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

def now(): return datetime.now(timezone.utc)

class ThreatHash(Base):
    __tablename__ = "threat_hashes"
    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    classification: Mapped[str] = mapped_column(String(32), default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(200), default="analyst")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class DomainReputation(Base):
    __tablename__ = "domain_reputation"
    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    classification: Mapped[str] = mapped_column(String(32), default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(200), default="analyst")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class PackageReputation(Base):
    __tablename__ = "package_reputation"
    id: Mapped[int] = mapped_column(primary_key=True)
    package_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    classification: Mapped[str] = mapped_column(String(32), default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(200), default="analyst")

class CertificateReputation(Base):
    __tablename__ = "certificate_reputation"
    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    classification: Mapped[str] = mapped_column(String(32), default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(200), default="analyst")

class ThreatReport(Base):
    __tablename__ = "threat_reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    indicator_type: Mapped[str] = mapped_column(String(30))
    indicator: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="SUBMITTED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
