from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from config import settings


class Base(DeclarativeBase):
    pass


class RunRecord(Base):
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="QUEUED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")

    def evidence(self) -> dict[str, Any]:
        try:
            return json.loads(self.evidence_json or "{}")
        except json.JSONDecodeError:
            return {}


engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def save_run(run_id: str, filename: str, status: str = "QUEUED", evidence: dict[str, Any] | None = None) -> None:
    with SessionLocal() as db:
        row = RunRecord(run_id=run_id, filename=filename, status=status, evidence_json=json.dumps(evidence or {}))
        db.add(row)
        db.commit()


def update_run(run_id: str, *, status: str | None = None, evidence: dict[str, Any] | None = None, completed: bool = False) -> None:
    with SessionLocal() as db:
        row = db.query(RunRecord).filter(RunRecord.run_id == run_id).first()
        if not row:
            return
        if status is not None:
            row.status = status
        if evidence is not None:
            row.evidence_json = json.dumps(evidence)
        if completed:
            row.completed_at = datetime.now(timezone.utc)
        db.commit()


def get_run(run_id: str) -> RunRecord | None:
    with SessionLocal() as db:
        return db.query(RunRecord).filter(RunRecord.run_id == run_id).first()
