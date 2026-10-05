from types import SimpleNamespace

from aegis.auth import create_token, decode_token, verify_credentials
from aegis.scanner import analyze_probe, replace_prompt, score_findings
from aegis.probes import Probe, build_probes


def test_replace_prompt_nested():
    src = {"messages": [{"role": "user", "content": "x {{PROMPT}} y"}]}
    out = replace_prompt(src, "HELLO")
    assert out["messages"][0]["content"] == "x HELLO y"


def test_detects_prompt_injection_canary():
    probe = Probe("prompt_injection_canary", "x", "prompt_injection", "x", canary="AEGIS_DIRECT_0123456789ABCDEF")
    findings = analyze_probe(probe, "AEGIS_DIRECT_0123456789ABCDEF")
    assert any(f.severity == "HIGH" for f in findings)


def test_detects_indirect_rag_canary():
    probe = Probe("indirect_prompt_injection", "x", "rag_security", "x", capabilities=("rag",), canary="AEGIS_RAG_0123456789ABCDEF")
    findings = analyze_probe(probe, "AEGIS_RAG_0123456789ABCDEF")
    assert any(f.category == "rag_security" for f in findings)


def test_probe_selection_by_capability():
    ids = {p.id for p in build_probes(["chat", "rag"])}
    assert "indirect_prompt_injection" in ids
    assert "mcp_privilege_boundary" not in ids


def test_detects_and_redacts_secret():
    probe = Probe("secret_exposure", "x", "data_leakage", "x")
    findings = analyze_probe(probe, "credential sk-ABCDEFGHIJKLMNOPQRSTUV")
    assert any(f.severity == "CRITICAL" and "REDACTED" in f.evidence for f in findings)


def test_score_never_negative():
    f = SimpleNamespace(severity="CRITICAL")
    assert score_findings([f, f, f, f]) == 0


def test_auth_roundtrip():
    assert verify_credentials("admin", "change-me")
    token = create_token("admin")
    assert decode_token(token) == "admin"


def test_target_schema_allows_default_project_for_legacy_frontend():
    from aegis.schemas import TargetCreate

    payload = TargetCreate(
        name="Demo",
        url="http://127.0.0.1:8010/vulnerable/chat",
        method="POST",
        provider="generic",
        capabilities=["chat"],
        request_template={"message": "{{PROMPT}}"},
        response_path="response",
        authorized=True,
    )
    assert payload.project_id is None
