from __future__ import annotations

from copy import deepcopy
from typing import ClassVar

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from soc_triage_agent.graph import build_graph
from soc_triage_agent.guardrails import PolicyDenied
from soc_triage_agent.mcp_client import validate_discovered_tools


def _initial(alert: dict, *, timeout: int = 300) -> dict:
    return {
        "alert": alert,
        "model_name": "stub",
        "approval_timeout_seconds": timeout,
        "audit_log": [],
    }


def test_authorized_triage_reaches_human_approval(sample_alert: dict) -> None:
    app = build_graph(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "authorized"}}
    paused = app.invoke(_initial(sample_alert), config=config)
    assert paused["authorized"] is True
    assert paused["verdict"]["label"] == "likely-compromise"
    assert paused["containment_recommendation"]["actioned"] is False
    assert paused["__interrupt__"]


def test_unauthorized_triage_is_blocked_before_tools(sample_alert: dict) -> None:
    alert = deepcopy(sample_alert)
    alert["tenant_id"] = "tenant-outside-scope"
    app = build_graph(checkpointer=InMemorySaver())
    result = app.invoke(
        _initial(alert), config={"configurable": {"thread_id": "blocked"}}
    )
    assert result["blocked"] is True
    assert result["status"] == "blocked"
    assert "enrichments" not in result
    assert "__interrupt__" not in result


def test_containment_is_not_actioned_when_rejected(sample_alert: dict) -> None:
    app = build_graph(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "rejected"}}
    paused = app.invoke(_initial(sample_alert), config=config)
    assert paused["containment_recommendation"]["actioned"] is False
    completed = app.invoke(
        Command(resume={"decision": "reject", "analyst_id": "analyst-test"}),
        config=config,
    )
    assert completed["approval"]["status"] == "rejected"
    assert completed["containment_recommendation"]["actioned"] is False


def test_human_approval_marks_recommendation_actioned(sample_alert: dict) -> None:
    app = build_graph(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "approved"}}
    app.invoke(_initial(sample_alert), config=config)
    completed = app.invoke(
        Command(resume={"decision": "approve", "analyst_id": "analyst-test"}),
        config=config,
    )
    assert completed["approval"]["status"] == "approved"
    assert completed["containment_recommendation"]["actioned"] is True
    assert completed["report"]["runtime_effect"].startswith(
        "recommendation recorded only"
    )


def test_approval_timeout_fails_closed(sample_alert: dict) -> None:
    app = build_graph(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "timeout"}}
    app.invoke(_initial(sample_alert), config=config)
    completed = app.invoke(
        Command(resume={"decision": "timeout", "analyst_id": "analyst-test"}),
        config=config,
    )
    assert completed["approval"]["status"] == "denied"
    assert "fail-closed" in completed["approval"]["reason"]
    assert completed["containment_recommendation"]["actioned"] is False


def test_unknown_mcp_tool_is_denied() -> None:
    class Tool:
        name = "unexpected_write_tool"
        input_schema: ClassVar[dict[str, object]] = {"type": "object", "properties": {}}

    with pytest.raises(PolicyDenied, match="inventory drift"):
        validate_discovered_tools([Tool()])
