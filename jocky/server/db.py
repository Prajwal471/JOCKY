"""SQLAlchemy ORM layer for JOCKY.

Single ``Base`` shared by server, evidence chain, capability decisions
and the coverage matrix. All runtime access routes through ``SessionLocal``.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from jocky.config import DATABASE_URL


class Base(DeclarativeBase):
    pass


def engine_factory(url: str = DATABASE_URL):
    from sqlalchemy import create_engine

    connect_args = {
        "check_same_thread": False
    } if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


engine = engine_factory()

from sqlalchemy.orm import sessionmaker  # noqa: E402

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(32))
    os_version: Mapped[str] = mapped_column(String(255), default="")
    collector_version: Mapped[str] = mapped_column(String(32), default="ctypes-0.1.0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Mission(Base):
    __tablename__ = "missions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    source_text: Mapped[str] = mapped_column(Text)
    jir: Mapped[dict] = mapped_column(JSON)
    jir_sha256: Mapped[str] = mapped_column(String(64), index=True)
    author: Mapped[str] = mapped_column(String(255), default="unknown")
    status: Mapped[str] = mapped_column(String(32), default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mission_id: Mapped[int] = mapped_column(ForeignKey("missions.id"), index=True)
    variant_index: Mapped[int] = mapped_column(Integer, default=0)
    jir_hash: Mapped[str] = mapped_column(String(64))
    sha256: Mapped[str] = mapped_column(String(64))
    llvm_ir_hash: Mapped[str] = mapped_column(String(64))
    passes: Mapped[list] = mapped_column(JSON, default=list)
    equivalence_proven: Mapped[bool] = mapped_column(default=False)
    compiled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    mission: Mapped[Mission] = relationship()


class CapabilityDecision(Base):
    __tablename__ = "capability_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mission_id: Mapped[int] = mapped_column(ForeignKey("missions.id"), index=True)
    capability: Mapped[str] = mapped_column(String(64), index=True)
    decision: Mapped[str] = mapped_column(String(16))  # ALLOW | DENY
    reason: Mapped[str] = mapped_column(Text)
    jir_hash: Mapped[str] = mapped_column(String(64))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    mission: Mapped[Mission] = relationship()


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    mission_id: Mapped[int] = mapped_column(ForeignKey("missions.id"), index=True, nullable=True)
    finding_type: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(255))
    privileges: Mapped[str] = mapped_column(String(64), default="none")
    payload: Mapped[dict] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    chain_index: Mapped[int] = mapped_column(Integer, default=0)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    chain_hash: Mapped[str] = mapped_column(String(64), index=True)
    capability: Mapped[str] = mapped_column(String(64), default="")
    signature: Mapped[str] = mapped_column(String(256), default="")

    endpoint: Mapped[Endpoint] = relationship()


class CoverageClause(Base):
    __tablename__ = "coverage_clauses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    clause_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32))  # LIVE | REGISTERED | MEASURED
    mechanism: Mapped[str] = mapped_column(Text, default="")
    protected_block: Mapped[str] = mapped_column(String(64), default="")
    notes: Mapped[str] = mapped_column(Text, default="")