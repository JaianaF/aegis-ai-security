from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class MCPRisk:
    tool: str
    severity: str
    title: str
    description: str
    remediation: str
    evidence: str


DANGEROUS_TERMS = {
    "shell": "HIGH",
    "exec": "HIGH",
    "command": "HIGH",
    "delete": "HIGH",
    "remove": "MEDIUM",
    "admin": "HIGH",
    "write": "MEDIUM",
    "filesystem": "MEDIUM",
    "file": "LOW",
    "http": "LOW",
    "fetch": "LOW",
    "sql": "HIGH",
    "database": "MEDIUM",
}
SENSITIVE_ARG_TERMS = {"command", "shell", "path", "url", "query", "sql", "token", "password", "secret", "key"}


def _tool_list(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    tools = manifest.get("tools", [])
    if isinstance(tools, dict):
        return [{"name": name, **(spec if isinstance(spec, dict) else {})} for name, spec in tools.items()]
    if isinstance(tools, list):
        return [t for t in tools if isinstance(t, dict)]
    return []


def audit_mcp_manifest(manifest: dict[str, Any]) -> list[MCPRisk]:
    risks: list[MCPRisk] = []
    tools = _tool_list(manifest)
    if not tools:
        return [MCPRisk(
            tool="<manifest>", severity="MEDIUM", title="No MCP tools discovered",
            description="The supplied manifest does not expose a recognizable tools list, so tool-level review could not be performed.",
            remediation="Provide a manifest containing tool names, descriptions and input schemas for static review.",
            evidence="tools missing or empty",
        )]

    for tool in tools:
        name = str(tool.get("name") or "<unnamed>")
        desc = str(tool.get("description") or "").strip()
        lowered = f"{name} {desc}".lower()
        normalized = lowered.replace("_", " ").replace("-", " ").replace("/", " ")
        if not desc:
            risks.append(MCPRisk(
                tool=name, severity="LOW", title="Tool has no description",
                description="The tool lacks a description, making intended scope and authorization boundaries harder to review.",
                remediation="Document the tool purpose, permitted resources, side effects and required authorization.",
                evidence=f"tool={name}",
            ))

        strongest: tuple[str, str] | None = None
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        for term, severity in DANGEROUS_TERMS.items():
            if term in normalized.split() and (strongest is None or order[severity] > order[strongest[1]]):
                strongest = (term, severity)
        if strongest:
            term, severity = strongest
            risks.append(MCPRisk(
                tool=name, severity=severity, title="Tool may perform sensitive or destructive actions",
                description="The tool name/description suggests access to a sensitive capability that should be strongly scoped and approved.",
                remediation="Use least-privilege credentials, explicit allowlists, server-side authorization, argument validation and human approval for irreversible actions.",
                evidence=f"matched capability term: {term}",
            ))

        schema = tool.get("inputSchema") or tool.get("input_schema") or tool.get("parameters") or {}
        if isinstance(schema, dict):
            if schema.get("additionalProperties") is True:
                risks.append(MCPRisk(
                    tool=name, severity="MEDIUM", title="Tool accepts unrestricted additional properties",
                    description="An open object schema can allow unexpected arguments to reach a privileged tool.",
                    remediation="Set additionalProperties=false where practical and explicitly define/validate accepted inputs.",
                    evidence="additionalProperties=true",
                ))
            props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
            sensitive = sorted(k for k in props if any(term in k.lower() for term in SENSITIVE_ARG_TERMS))
            if sensitive:
                risks.append(MCPRisk(
                    tool=name, severity="MEDIUM", title="Tool exposes security-sensitive arguments",
                    description="The tool schema includes arguments that can influence files, networks, commands, queries or credentials.",
                    remediation="Validate values against strict allowlists, prevent arbitrary command/query construction, redact secrets and require authorization for privileged inputs.",
                    evidence="sensitive args: " + ", ".join(sensitive[:8]),
                ))

    deduped: list[MCPRisk] = []
    seen = set()
    for risk in risks:
        key = (risk.tool, risk.title, risk.evidence)
        if key not in seen:
            seen.add(key)
            deduped.append(risk)
    return deduped


def risks_to_dict(risks: list[MCPRisk]) -> list[dict[str, Any]]:
    return [asdict(r) for r in risks]
