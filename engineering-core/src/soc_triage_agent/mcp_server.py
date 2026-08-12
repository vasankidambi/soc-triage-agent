"""Local MCP server exposing synthetic enrichment and request-only containment tools."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Literal

from mcp.server import MCPServer

server = MCPServer(
    "soc-triage-mock-tools",
    description="Synthetic defensive SOC enrichment tools",
    version="0.1.0",
)


def _fixture_path() -> Path:
    configured = os.getenv("SOC_TRIAGE_FIXTURE_DIR")
    candidates = [
        Path(configured) if configured else None,
        Path.cwd() / "sample_data",
        Path(__file__).resolve().parents[2] / "sample_data",
        Path(sys.prefix) / "share" / "soc-triage-agent" / "sample_data",
    ]
    for candidate in candidates:
        if candidate and (candidate / "enrichments.json").is_file():
            return candidate / "enrichments.json"
    raise RuntimeError("sample_data/enrichments.json was not found")


def _fixtures() -> dict[str, Any]:
    with _fixture_path().open(encoding="utf-8") as handle:
        return json.load(handle)


@server.tool(structured_output=True)
def identity_lookup(user_id: str) -> dict[str, Any]:
    """Return synthetic identity and managed-device context for one user."""
    data = _fixtures()["identity_lookup"]
    if user_id != data["user_id"]:
        raise ValueError("synthetic user was not found")
    return data


@server.tool(structured_output=True)
def signin_history(user_id: str) -> dict[str, Any]:
    """Return synthetic recent sign-in activity for one user."""
    data = _fixtures()["signin_history"]
    if user_id != data["user_id"]:
        raise ValueError("synthetic user was not found")
    return data


@server.tool(structured_output=True)
def ip_reputation(ip_address: str) -> dict[str, Any]:
    """Return a synthetic defensive reputation assessment for one address."""
    data = _fixtures()["ip_reputation"]
    if ip_address != data["ip_address"]:
        return {
            "ip_address": ip_address,
            "reputation": "unknown",
            "risk_score": 0.0,
            "signals": [],
        }
    return data


@server.tool(structured_output=True)
def siem_recent_events(user_id: str) -> dict[str, Any]:
    """Return synthetic recent security events for one user."""
    data = _fixtures()["siem_recent_events"]
    if user_id != data["user_id"]:
        raise ValueError("synthetic user was not found")
    return data


@server.tool(structured_output=True)
def recommend_account_containment(
    alert_id: str,
    user_id: str,
    verdict: Literal["likely-compromise"],
    authorized: bool,
    approval_required: bool,
) -> dict[str, Any]:
    """Create a request-only containment recommendation; never change an account."""
    if not authorized or not approval_required or verdict != "likely-compromise":
        raise ValueError("containment recommendation denied by server-side policy")
    return {
        "recommendation_id": f"rec-{alert_id.lower()}",
        "user_id": user_id,
        "actions": ["require_password_reset", "revoke_active_sessions"],
        "reason": "Synthetic correlated evidence indicates likely account compromise.",
        "request_only": True,
        "approval_required": True,
        "actioned": False,
        "action_status": "pending-human-approval",
    }


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
