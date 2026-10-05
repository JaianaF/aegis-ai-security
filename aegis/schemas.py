from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl


Provider = Literal["generic", "openai", "anthropic", "gemini", "azure_openai", "ollama"]
Capability = Literal["chat", "rag", "agent", "mcp"]
ScanEngine = Literal["builtin"]


class LoginIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    token: str
    token_type: str = "bearer"
    username: str


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class OrganizationOut(BaseModel):
    id: int
    name: str
    created_at: datetime
    model_config = {"from_attributes": True}


class ProjectCreate(BaseModel):
    organization_id: int
    name: str = Field(min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=2000)


class ProjectOut(BaseModel):
    id: int
    organization_id: int
    name: str
    description: str | None
    created_at: datetime
    model_config = {"from_attributes": True}


class TargetCreate(BaseModel):
    project_id: int
    name: str = Field(min_length=2, max_length=120)
    url: HttpUrl
    method: Literal["POST", "PUT", "PATCH"] = "POST"
    provider: Provider = "generic"
    capabilities: list[Capability] = Field(default_factory=lambda: ["chat"], min_length=1)
    request_template: dict[str, Any]
    response_path: str | None = None
    authorized: bool = False


class TargetOut(BaseModel):
    id: int
    project_id: int
    name: str
    url: str
    method: str
    provider: str
    capabilities: list[str]
    request_template: dict[str, Any]
    response_path: str | None
    authorized: bool
    created_at: datetime
    model_config = {"from_attributes": True}


class ScanCreate(BaseModel):
    target_id: int
    engine: ScanEngine = "builtin"
    headers: dict[str, str] = Field(default_factory=dict, description="Encrypted temporarily for the worker and deleted after execution.")
    categories: list[str] = Field(default_factory=list, description="Optional category filter.")


class RetestCreate(BaseModel):
    headers: dict[str, str] = Field(default_factory=dict, description="Encrypted temporarily for the worker and deleted after execution.")


class FindingOut(BaseModel):
    id: int
    probe_id: str
    category: str
    title: str
    severity: str
    confidence: str
    description: str
    evidence: str
    remediation: str
    standard_refs: list[str]
    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    target_id: int
    parent_scan_id: int | None
    engine: str
    status: str
    score: int | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    findings: list[FindingOut]
    regression: dict[str, Any] = Field(default_factory=dict)
    model_config = {"from_attributes": True}


class AuditEventOut(BaseModel):
    id: int
    actor: str
    action: str
    entity_type: str
    entity_id: int | None
    details: dict[str, Any]
    created_at: datetime
    model_config = {"from_attributes": True}


class MCPAuditRequest(BaseModel):
    manifest: dict[str, Any]


class MCPRiskOut(BaseModel):
    tool: str
    severity: str
    title: str
    description: str
    remediation: str
    evidence: str
