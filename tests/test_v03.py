from types import SimpleNamespace

from aegis.integrations import integration_status
from aegis.job_secrets import seal_job_payload, unseal_job_payload
from aegis.mcp_audit import audit_mcp_manifest
from aegis.reports import scan_to_sarif


def test_job_payload_roundtrip():
    payload = {
        "headers": {"Authorization": "Bearer synthetic-test-token"},
        "categories": ["prompt_injection"],
    }
    sealed = seal_job_payload(payload)
    assert "synthetic-test-token" not in sealed
    assert unseal_job_payload(sealed) == payload


def test_mcp_audit_flags_command_tool():
    risks = audit_mcp_manifest({
        "tools": [{
            "name": "admin_exec",
            "description": "Execute admin command",
            "inputSchema": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "additionalProperties": False,
            },
        }]
    })
    assert any(r.severity == "HIGH" for r in risks)
    assert any("command" in r.evidence.lower() for r in risks)


def test_mcp_audit_flags_open_schema():
    risks = audit_mcp_manifest({
        "tools": [{
            "name": "lookup",
            "description": "Look up a record",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": True,
            },
        }]
    })
    assert any(r.title == "Tool accepts unrestricted additional properties" for r in risks)


def test_integration_status_always_has_builtin_engine():
    status = integration_status()
    assert status["builtin"]["available"] is True
    assert status["builtin"]["mode"] == "active"
    assert "promptfoo" in status
    assert "garak" in status


def test_sarif_report_contains_security_result():
    finding = SimpleNamespace(
        probe_id="prompt_injection_canary",
        category="prompt_injection",
        title="Direct prompt injection instruction was followed",
        severity="HIGH",
        confidence="HIGH",
        description="Synthetic finding for report validation.",
        evidence="AEGIS_DIRECT_TEST",
        remediation="Separate instructions from untrusted data.",
        standard_refs=["OWASP GenAI: Prompt Injection"],
    )
    scan = SimpleNamespace(id=42, engine="builtin", findings=[finding])
    target = SimpleNamespace(url="https://example.test/chat")

    sarif = scan_to_sarif(scan, target)

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["version"] == "0.3.0"
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "prompt_injection_canary"
    assert result["level"] == "error"
    assert result["properties"]["scanId"] == 42
