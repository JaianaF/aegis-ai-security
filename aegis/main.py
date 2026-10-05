from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .auth import create_token, require_user, verify_credentials
from .db import SessionLocal, init_db
from .models import Finding, Scan, Target
from .providers import PROVIDER_PRESETS
from .reports import scan_to_dict, scan_to_sarif
from .scanner import run_scan, score_findings
from .schemas import LoginIn, RetestCreate, ScanCreate, ScanOut, TargetCreate, TargetOut, TokenOut
from .security import UnsafeTargetError, validate_target_url

app = FastAPI(title="AegisAI Security", version="0.2.0")
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.on_event("startup")
def startup() -> None:
    init_db()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "aegis-ai-security", "version": "0.2.0"}


@app.post("/api/login", response_model=TokenOut)
def login(payload: LoginIn):
    if not verify_credentials(payload.username, payload.password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    return TokenOut(token=create_token(payload.username), username=payload.username)


@app.get("/api/provider-presets")
def provider_presets(_: str = Depends(require_user)):
    return PROVIDER_PRESETS


@app.post("/api/targets", response_model=TargetOut)
def create_target(payload: TargetCreate, db: Session = Depends(get_db), _: str = Depends(require_user)):
    if not payload.authorized:
        raise HTTPException(400, "You must confirm that you are authorized to test this target.")
    if "{{PROMPT}}" not in str(payload.request_template):
        raise HTTPException(400, "request_template must contain the {{PROMPT}} placeholder.")
    try:
        validate_target_url(str(payload.url))
    except UnsafeTargetError as exc:
        raise HTTPException(400, str(exc)) from exc

    target = Target(
        name=payload.name,
        url=str(payload.url),
        method=payload.method,
        provider=payload.provider,
        capabilities=list(dict.fromkeys(payload.capabilities)),
        request_template=payload.request_template,
        response_path=payload.response_path,
        authorized=True,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@app.get("/api/targets", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db), _: str = Depends(require_user)):
    return db.scalars(select(Target).order_by(Target.id.desc())).all()


async def _execute_scan(scan: Scan, target: Target, headers: dict[str, str], categories: list[str], db: Session) -> None:
    try:
        finding_data = await run_scan(target, headers, categories)
        for item in finding_data:
            db.add(Finding(scan_id=scan.id, **item.__dict__))
        scan.score = score_findings(finding_data)
        scan.status = "completed"
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as exc:
        scan.status = "failed"
        scan.error = f"{type(exc).__name__}: {str(exc)[:500]}"
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()


def _load_scan(scan_id: int, db: Session) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings)))
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return scan


def _regression(scan: Scan, db: Session) -> dict:
    previous = db.scalar(
        select(Scan)
        .where(Scan.target_id == scan.target_id, Scan.id < scan.id, Scan.status == "completed")
        .options(selectinload(Scan.findings))
        .order_by(Scan.id.desc())
        .limit(1)
    )
    if not previous:
        return {"baseline": True, "new": 0, "resolved": 0, "unchanged": len(scan.findings), "previous_scan_id": None}
    current_keys = {(f.probe_id, f.title) for f in scan.findings}
    previous_keys = {(f.probe_id, f.title) for f in previous.findings}
    return {
        "baseline": False,
        "new": len(current_keys - previous_keys),
        "resolved": len(previous_keys - current_keys),
        "unchanged": len(current_keys & previous_keys),
        "previous_scan_id": previous.id,
        "score_delta": (scan.score or 0) - (previous.score or 0),
    }


def _scan_out(scan: Scan, db: Session) -> ScanOut:
    out = ScanOut.model_validate(scan)
    out.regression = _regression(scan, db)
    return out


@app.post("/api/scans", response_model=ScanOut)
async def create_scan(payload: ScanCreate, db: Session = Depends(get_db), _: str = Depends(require_user)):
    target = db.get(Target, payload.target_id)
    if not target:
        raise HTTPException(404, "Target not found.")
    if not target.authorized:
        raise HTTPException(403, "Target is not marked as authorized.")

    scan = Scan(target_id=target.id, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    await _execute_scan(scan, target, payload.headers, payload.categories, db)
    return _scan_out(_load_scan(scan.id, db), db)


@app.post("/api/scans/{scan_id}/retest", response_model=ScanOut)
async def retest_scan(scan_id: int, payload: RetestCreate, db: Session = Depends(get_db), _: str = Depends(require_user)):
    source = _load_scan(scan_id, db)
    target = db.get(Target, source.target_id)
    if not target or not target.authorized:
        raise HTTPException(403, "Target unavailable or not authorized.")
    scan = Scan(target_id=target.id, parent_scan_id=source.id, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    await _execute_scan(scan, target, payload.headers, [], db)
    return _scan_out(_load_scan(scan.id, db), db)


@app.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), _: str = Depends(require_user)):
    return _scan_out(_load_scan(scan_id, db), db)


@app.get("/api/scans", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db), _: str = Depends(require_user)):
    scans = db.scalars(
        select(Scan).options(selectinload(Scan.findings)).order_by(Scan.id.desc()).limit(50)
    ).all()
    return [_scan_out(scan, db) for scan in scans]


@app.get("/api/scans/{scan_id}/report.json")
def report_json(scan_id: int, db: Session = Depends(get_db), _: str = Depends(require_user)):
    scan = _load_scan(scan_id, db)
    payload = scan_to_dict(scan)
    payload["regression"] = _regression(scan, db)
    return JSONResponse(payload, headers={"Content-Disposition": f'attachment; filename="aegis-scan-{scan_id}.json"'})


@app.get("/api/scans/{scan_id}/report.sarif")
def report_sarif(scan_id: int, db: Session = Depends(get_db), _: str = Depends(require_user)):
    scan = _load_scan(scan_id, db)
    target = db.get(Target, scan.target_id)
    return JSONResponse(scan_to_sarif(scan, target), media_type="application/sarif+json", headers={"Content-Disposition": f'attachment; filename="aegis-scan-{scan_id}.sarif"'})
