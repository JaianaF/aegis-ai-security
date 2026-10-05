from __future__ import annotations

import shutil


def integration_status() -> dict:
    return {
        "builtin": {"available": True, "mode": "active", "detail": "Built-in non-destructive AegisAI probes."},
        "promptfoo": {
            "available": bool(shutil.which("promptfoo")),
            "mode": "optional",
            "detail": "Detected on PATH." if shutil.which("promptfoo") else "Not installed. Integration is optional and disabled by default.",
        },
        "garak": {
            "available": bool(shutil.which("garak")),
            "mode": "optional",
            "detail": "Detected on PATH." if shutil.which("garak") else "Not installed. Integration is optional and disabled by default.",
        },
    }
