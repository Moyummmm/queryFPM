from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def load_template_manifest(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def allowed_templates_for_llm(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    allowed: list[dict[str, Any]] = []
    for template in manifest.get("templates", []):
        if template.get("enabled", True) is False:
            continue
        allowed.append(
            {
                "template_id": template["id"],
                "description": template.get("description"),
                "missing_evidence": template.get("missing_evidence"),
                "parameters": template.get("parameters", []),
                "cwe_categories": template.get("cwe_categories", []),
            }
        )
    return allowed


def find_template(manifest: dict[str, Any], template_id: str) -> dict[str, Any] | None:
    for template in manifest.get("templates", []):
        if template.get("id") == template_id:
            return template
    return None


def render_template(template: dict[str, Any], parameters: dict[str, Any], template_root: str | Path) -> str:
    path = Path(template_root) / template["file"]
    text = path.read_text(encoding="utf-8")

    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        value = parameters.get(key, "")
        if isinstance(value, str):
            return json.dumps(value)
        return json.dumps(value)

    return re.sub(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}", replace, text)
