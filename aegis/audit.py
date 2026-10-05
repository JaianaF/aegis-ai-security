from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditEvent


def record_event(db: Session, actor: str, action: str, entity_type: str, entity_id: int | None = None, details: dict | None = None) -> None:
    db.add(AuditEvent(actor=actor, action=action, entity_type=entity_type, entity_id=entity_id, details=details or {}))
