"""Run the local graph, display the interrupt, and resume with an analyst decision."""

from __future__ import annotations

import argparse
import json
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from .graph import build_graph


def _project_root() -> Path:
    working_directory = Path.cwd()
    if (working_directory / "sample_data" / "suspicious_login_alert.json").is_file():
        return working_directory
    return Path(__file__).resolve().parents[2]


PROJECT_ROOT = _project_root()


def _load_alert(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _decision_payload(choice: str) -> dict[str, Any]:
    if choice == "approve":
        return {
            "decision": "approve",
            "analyst_id": "analyst-local",
            "note": "Synthetic demo approval.",
        }
    if choice == "reject":
        return {
            "decision": "reject",
            "analyst_id": "analyst-local",
            "note": "Synthetic demo rejection.",
        }
    return {
        "decision": "timeout",
        "analyst_id": "analyst-local",
        "note": "No response before deadline.",
    }


def _ask_for_decision() -> str:
    choice = (
        input("Decision [approve/reject/timeout] (default reject): ").strip().lower()
        or "reject"
    )
    if choice not in {"approve", "reject", "timeout"}:
        print("Unrecognized decision; failing closed as reject.")
        return "reject"
    return choice


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the synthetic SOC triage workflow locally."
    )
    parser.add_argument(
        "--alert",
        type=Path,
        default=PROJECT_ROOT / "sample_data" / "suspicious_login_alert.json",
    )
    parser.add_argument("--decision", choices=["approve", "reject", "timeout"])
    parser.add_argument("--thread-id", default=f"triage-{uuid.uuid4()}")
    parser.add_argument("--approval-timeout", type=int, default=300)
    args = parser.parse_args()

    checkpoint_dir = PROJECT_ROOT / ".local"
    checkpoint_dir.mkdir(exist_ok=True)
    config = {"configurable": {"thread_id": args.thread_id}}
    initial = {
        "alert": _load_alert(args.alert),
        "model_name": "stub",
        "approval_timeout_seconds": args.approval_timeout,
        "audit_log": [],
    }

    with closing(
        sqlite3.connect(checkpoint_dir / "checkpoints.sqlite", check_same_thread=False)
    ) as connection:
        checkpointer = SqliteSaver(connection)
        app = build_graph(checkpointer=checkpointer)

        print(f"Thread: {args.thread_id}")
        print(
            "Starting: intake -> plan -> parallel enrichment -> correlate -> verdict -> risk gate"
        )
        paused = app.invoke(initial, config=config)
        if paused.get("blocked"):
            print(
                json.dumps(
                    {"status": "blocked", "reason": paused.get("block_reason")},
                    indent=2,
                )
            )
            return
        interrupts = paused.get("__interrupt__", [])
        if not interrupts:
            print(json.dumps(paused.get("report", paused), indent=2, sort_keys=True))
            return
        print("\nHUMAN APPROVAL PAUSE")
        print(json.dumps(interrupts[0].value, indent=2, sort_keys=True))
        choice = args.decision or _ask_for_decision()
        print(f"\nResuming the same checkpointed thread with decision={choice}")
        completed = app.invoke(Command(resume=_decision_payload(choice)), config=config)
        print("\nAUDIT TRACE")
        for item in completed["audit_log"]:
            print(f"{item['node']}: {item['decision']} - {item['detail']}")
        print("\nNORMALIZED REPORT")
        print(json.dumps(completed["report"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
