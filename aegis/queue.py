from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from .config import WORKER_STALE_MINUTES
from .db import SessionLocal, engine
from .models import Finding, Scan, Target
from .job_secrets import unseal_job_payload
from .scanner import run_scan, score_findings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def requeue_stale_scans() -> int:
    cutoff = utcnow() - timedelta(minutes=WORKER_STALE_MINUTES)
    with SessionLocal() as db:
        result = db.execute(
            update(Scan)
            .where(Scan.status == "running", Scan.started_at.is_not(None), Scan.started_at < cutoff)
            .values(status="queued", started_at=None, error="Recovered stale worker job")
        )
        db.commit()
        return int(result.rowcount or 0)


def claim_next_scan() -> int | None:
    with SessionLocal() as db:
        stmt = select(Scan).where(Scan.status == "queued").order_by(Scan.id.asc()).limit(1)
        if engine.dialect.name == "postgresql":
            stmt = stmt.with_for_update(skip_locked=True)
        scan = db.scalar(stmt)
        if not scan:
            return None
        scan.status = "running"
        scan.started_at = utcnow()
        scan.error = None
        db.commit()
        return scan.id


async def execute_scan_job(scan_id: int) -> None:
    with SessionLocal() as db:
        scan = db.scalar(select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings)))
        if not scan:
            return
        target = db.get(Target, scan.target_id)
        if not target:
            scan.status = "failed"
            scan.error = "Target not found."
            scan.finished_at = utcnow()
            scan.job_payload = None
            db.commit()
            return
        try:
            payload = unseal_job_payload(scan.job_payload or "")
            headers = payload.get("headers") or {}
            categories = payload.get("categories") or []
            findings = await run_scan(target, headers, categories)
            for old in list(scan.findings):
                db.delete(old)
            db.flush()
            for item in findings:
                db.add(Finding(scan_id=scan.id, **item.__dict__))
            scan.score = score_findings(findings)
            scan.status = "completed"
            scan.error = None
        except Exception as exc:
            scan.status = "failed"
            scan.error = f"{type(exc).__name__}: {str(exc)[:500]}"
        finally:
            scan.job_payload = None
            scan.finished_at = utcnow()
            db.commit()
