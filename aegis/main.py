from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from .audit import record_event
from .auth import create_token, require_user, verify_credentials
from .db import SessionLocal, ensure_default_workspace, init_db
from .integrations import integration_status
from .job_secrets import seal_job_payload
from .mcp_audit import audit_mcp_manifest, risks_to_dict
from .models import AuditEvent, Organization, Project, Scan, Target
from .providers import PROVIDER_PRESETS
from .reports import scan_to_dict, scan_to_sarif
from .schemas import (
    AuditEventOut,
    LoginIn,
    MCPAuditRequest,
    MCPRiskOut,
    OrganizationCreate,
    OrganizationOut,
    ProjectCreate,
    ProjectOut,
    RetestCreate,
    ScanCreate,
    ScanOut,
    TargetCreate,
    TargetOut,
    TokenOut,
)
from .security import UnsafeTargetError, validate_target_url

app = FastAPI(title="AegisAI Security", version="0.3.0")
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
    return {"status": "ok", "service": "aegis-ai-security", "version": "0.3.0", "queue": "database-worker"}


@app.post("/api/login", response_model=TokenOut)
def login(payload: LoginIn):
    if not verify_credentials(payload.username, payload.password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    return TokenOut(token=create_token(payload.username), username=payload.username)


@app.get("/api/provider-presets")
def provider_presets(_: str = Depends(require_user)):
    return PROVIDER_PRESETS


@app.get("/api/integrations")
def integrations(_: str = Depends(require_user)):
    return integration_status()


@app.get("/api/organizations", response_model=list[OrganizationOut])
def list_organizations(db: Session = Depends(get_db), _: str = Depends(require_user)):
    return db.scalars(select(Organization).order_by(Organization.id.asc())).all()


@app.post("/api/organizations", response_model=OrganizationOut)
def create_organization(payload: OrganizationCreate, db: Session = Depends(get_db), actor: str = Depends(require_user)):
    org = Organization(name=payload.name.strip())
    db.add(org)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "An organization with this name already exists.") from exc
    record_event(db, actor, "organization.created", "organization", org.id, {"name": org.name})
    db.commit()
    db.refresh(org)
    return org


@app.get("/api/projects", response_model=list[ProjectOut])
def list_projects(
    organization_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(require_user),
):
    stmt = select(Project).order_by(Project.id.asc())
    if organization_id is not None:
        stmt = stmt.where(Project.organization_id == organization_id)
    return db.scalars(stmt).all()


@app.post("/api/projects", response_model=ProjectOut)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db), actor: str = Depends(require_user)):
    if not db.get(Organization, payload.organization_id):
        raise HTTPException(404, "Organization not found.")
    project = Project(
        organization_id=payload.organization_id,
        name=payload.name.strip(),
        description=payload.description,
    )
    db.add(project)
    db.flush()
    record_event(db, actor, "project.created", "project", project.id, {"name": project.name, "organization_id": project.organization_id})
    db.commit()
    db.refresh(project)
    return project


@app.post("/api/targets", response_model=TargetOut)
def create_target(payload: TargetCreate, db: Session = Depends(get_db), actor: str = Depends(require_user)):
    if not payload.authorized:
        raise HTTPException(400, "You must confirm that you are authorized to test this target.")
    if not db.get(Project, payload.project_id):
        raise HTTPException(404, "Project not found.")
    if "{{PROMPT}}" not in str(payload.request_template):
        raise HTTPException(400, "request_template must contain the {{PROMPT}} placeholder.")
    try:
        validate_target_url(str(payload.url))
    except UnsafeTargetError as exc:
        raise HTTPException(400, str(exc)) from exc

    target = Target(
        project_id=payload.project_id,
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
    db.flush()
    record_event(db, actor, "target.created", "target", target.id, {"name": target.name, "project_id": target.project_id, "provider": target.provider})
    db.commit()
    db.refresh(target)
    return target


@app.get("/api/targets", response_model=list[TargetOut])
def list_targets(
    project_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(require_user),
):
    stmt = select(Target).order_by(Target.id.desc())
    if project_id is not None:
        stmt = stmt.where(Target.project_id == project_id)
    return db.scalars(stmt).all()


def _load_scan(scan_id: int, db: Session) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings)))
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return scan


def _regression(scan: Scan, db: Session) -> dict:
    if scan.status != "completed":
        return {"pending": True, "baseline": False, "new": 0, "resolved": 0, "unchanged": 0, "previous_scan_id": None}
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


def _queue_scan(db: Session, target: Target, actor: str, headers: dict[str, str], categories: list[str], parent_scan_id: int | None = None, engine: str = "builtin") -> Scan:
    encrypted_payload = seal_job_payload({"headers": headers, "categories": categories})
    scan = Scan(
        target_id=target.id,
        parent_scan_id=parent_scan_id,
        engine=engine,
        status="queued",
        job_payload=encrypted_payload,
    )
    db.add(scan)
    db.flush()
    record_event(db, actor, "scan.queued", "scan", scan.id, {"target_id": target.id, "engine": engine, "retest_of": parent_scan_id})
    db.commit()
    return _load_scan(scan.id, db)


@app.post("/api/scans", response_model=ScanOut, status_code=202)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db), actor: str = Depends(require_user)):
    target = db.get(Target, payload.target_id)
    if not target:
        raise HTTPException(404, "Target not found.")
    if not target.authorized:
        raise HTTPException(403, "Target is not marked as authorized.")
    if payload.engine != "builtin":
        raise HTTPException(400, "Only the built-in engine is active in v0.3. Promptfoo/garak are detected as optional integrations but are not executed automatically.")
    return _scan_out(_queue_scan(db, target, actor, payload.headers, payload.categories, engine=payload.engine), db)


@app.post("/api/scans/{scan_id}/retest", response_model=ScanOut, status_code=202)
def retest_scan(scan_id: int, payload: RetestCreate, db: Session = Depends(get_db), actor: str = Depends(require_user)):
    source = _load_scan(scan_id, db)
    target = db.get(Target, source.target_id)
    if not target or not target.authorized:
        raise HTTPException(403, "Target unavailable or not authorized.")
    return _scan_out(_queue_scan(db, target, actor, payload.headers, [], parent_scan_id=source.id, engine=source.engine), db)


@app.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), _: str = Depends(require_user)):
    return _scan_out(_load_scan(scan_id, db), db)


@app.get("/api/scans", response_model=list[ScanOut])
def list_scans(
    project_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(require_user),
):
    stmt = select(Scan).join(Target).options(selectinload(Scan.findings)).order_by(Scan.id.desc()).limit(100)
    if project_id is not None:
        stmt = stmt.where(Target.project_id == project_id)
    scans = db.scalars(stmt).unique().all()
    return [_scan_out(scan, db) for scan in scans]


@app.get("/api/scans/{scan_id}/report.json")
def report_json(scan_id: int, db: Session = Depends(get_db), actor: str = Depends(require_user)):
    scan = _load_scan(scan_id, db)
    payload = scan_to_dict(scan)
    payload["regression"] = _regression(scan, db)
    record_event(db, actor, "scan.report.json", "scan", scan.id)
    db.commit()
    return JSONResponse(payload, headers={"Content-Disposition": f'attachment; filename="aegis-scan-{scan_id}.json"'})


@app.get("/api/scans/{scan_id}/report.sarif")
def report_sarif(scan_id: int, db: Session = Depends(get_db), actor: str = Depends(require_user)):
    scan = _load_scan(scan_id, db)
    target = db.get(Target, scan.target_id)
    record_event(db, actor, "scan.report.sarif", "scan", scan.id)
    db.commit()
    return JSONResponse(scan_to_sarif(scan, target), media_type="application/sarif+json", headers={"Content-Disposition": f'attachment; filename="aegis-scan-{scan_id}.sarif"'})


@app.post("/api/mcp/audit", response_model=list[MCPRiskOut])
def audit_mcp(payload: MCPAuditRequest, db: Session = Depends(get_db), actor: str = Depends(require_user)):
    risks = risks_to_dict(audit_mcp_manifest(payload.manifest))
    record_event(db, actor, "mcp.audit", "mcp_manifest", None, {"risk_count": len(risks)})
    db.commit()
    return risks


@app.get("/api/audit-events", response_model=list[AuditEventOut])
def audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: str = Depends(require_user),
):
    return db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)).all()


@app.post("/api/bootstrap")
def bootstrap_workspace(db: Session = Depends(get_db), actor: str = Depends(require_user)):
    org_id, project_id = ensure_default_workspace()
    record_event(db, actor, "workspace.bootstrap", "project", project_id, {"organization_id": org_id})
    db.commit()
    return {"organization_id": org_id, "project_id": project_id}
