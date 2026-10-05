from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import DATABASE_URL, DEFAULT_ORG_NAME, DEFAULT_PROJECT_NAME


class Base(DeclarativeBase):
    pass


connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db() -> None:
    from . import models  # noqa: F401
    Base.metadata.create_all(engine)
    ensure_default_workspace()


def ensure_default_workspace() -> tuple[int, int]:
    from .models import Organization, Project

    with SessionLocal() as db:
        org = db.scalar(select(Organization).where(Organization.name == DEFAULT_ORG_NAME))
        if not org:
            org = Organization(name=DEFAULT_ORG_NAME)
            db.add(org)
            db.flush()
        project = db.scalar(
            select(Project).where(Project.organization_id == org.id, Project.name == DEFAULT_PROJECT_NAME)
        )
        if not project:
            project = Project(organization_id=org.id, name=DEFAULT_PROJECT_NAME, description="Default workspace created by AegisAI Security.")
            db.add(project)
            db.flush()
        ids = (org.id, project.id)
        db.commit()
        return ids
