"""Invoke the graph through a running local LangGraph Agent Server."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
from langgraph_sdk import get_client


def _project_root() -> Path:
    working_directory = Path.cwd()
    if (working_directory / "sample_data" / "suspicious_login_alert.json").is_file():
        return working_directory
    return Path(__file__).resolve().parents[2]


PROJECT_ROOT = _project_root()


def _alert() -> dict[str, Any]:
    with (PROJECT_ROOT / "sample_data" / "suspicious_login_alert.json").open(
        encoding="utf-8"
    ) as handle:
        return json.load(handle)


async def run(url: str, decision: str) -> None:
    async with httpx.AsyncClient() as http:
        health = await http.get(f"{url}/ok", timeout=5.0)
    print(f"Server health: HTTP {health.status_code} {health.text.strip()}")
    client = get_client(url=url)
    thread = await client.threads.create(graph_id="soc_triage")
    thread_id = thread["thread_id"]
    paused = await client.runs.wait(
        thread_id,
        "soc_triage",
        input={
            "alert": _alert(),
            "model_name": "stub",
            "approval_timeout_seconds": 300,
            "audit_log": [],
        },
    )
    print(f"SDK thread: {thread_id}")
    print(f"Paused for approval: {bool(paused.get('__interrupt__'))}")
    response = {
        "decision": decision,
        "analyst_id": "analyst-sdk",
        "note": "Synthetic SDK demonstration.",
    }
    completed = await client.runs.wait(
        thread_id,
        "soc_triage",
        command={"resume": response},
    )
    print(json.dumps(completed["report"], indent=2, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description="Call a local LangGraph Agent Server.")
    parser.add_argument("--url", default="http://127.0.0.1:8123")
    parser.add_argument(
        "--decision", choices=["approve", "reject", "timeout"], default="reject"
    )
    args = parser.parse_args()
    asyncio.run(run(args.url, args.decision))


if __name__ == "__main__":
    main()
