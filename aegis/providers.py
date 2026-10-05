from __future__ import annotations

PROVIDER_PRESETS = {
    "generic": {
        "label": "Generic HTTP API",
        "url": "https://example.com/api/chat",
        "template": {"message": "{{PROMPT}}"},
        "response_path": "response",
        "auth_hint": "Add authorization headers only when starting a scan. They are not persisted.",
    },
    "openai": {
        "label": "OpenAI-compatible",
        "url": "https://api.openai.com/v1/chat/completions",
        "template": {"model": "gpt-5.6", "messages": [{"role": "user", "content": "{{PROMPT}}"}]},
        "response_path": "choices.0.message.content",
        "auth_hint": "Use Authorization: Bearer <API_KEY> as an ephemeral scan header.",
    },
    "anthropic": {
        "label": "Anthropic Messages API",
        "url": "https://api.anthropic.com/v1/messages",
        "template": {"model": "claude-sonnet-4-5", "max_tokens": 512, "messages": [{"role": "user", "content": "{{PROMPT}}"}]},
        "response_path": "content.0.text",
        "auth_hint": "Use x-api-key and anthropic-version headers as ephemeral scan headers.",
    },
    "gemini": {
        "label": "Google Gemini",
        "url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
        "template": {"contents": [{"parts": [{"text": "{{PROMPT}}"}]}]},
        "response_path": "candidates.0.content.parts.0.text",
        "auth_hint": "Use x-goog-api-key as an ephemeral scan header; do not put keys in the URL.",
    },
    "azure_openai": {
        "label": "Azure OpenAI",
        "url": "https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT/chat/completions?api-version=2025-04-01-preview",
        "template": {"messages": [{"role": "user", "content": "{{PROMPT}}"}]},
        "response_path": "choices.0.message.content",
        "auth_hint": "Replace resource/deployment in the URL and use api-key as an ephemeral scan header.",
    },
    "ollama": {
        "label": "Ollama",
        "url": "http://127.0.0.1:11434/api/chat",
        "template": {"model": "llama3.2", "stream": False, "messages": [{"role": "user", "content": "{{PROMPT}}"}]},
        "response_path": "message.content",
        "auth_hint": "Local targets require ALLOW_PRIVATE_TARGETS=true and should only be used in an authorized lab.",
    },
}
