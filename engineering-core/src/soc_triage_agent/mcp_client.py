"""MCP client broker with allowlisting, schema pinning, and complete mediation."""

from __future__ import annotations

import asyncio
import sys
from contextlib import AsyncExitStack
from types import TracebackType
from typing import Any, Self

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

from .guardrails import (
    CONTAINMENT_TOOL,
    READ_ONLY_TOOLS,
    PolicyDenied,
    authorize_tool_call,
    sanitize_untrusted_payload,
)

PINNED_INPUT_SCHEMAS: dict[str, dict[str, Any]] = {
    "identity_lookup": {
        "type": "object",
        "properties": {"user_id": {"type": "string"}},
        "required": ["user_id"],
    },
    "signin_history": {
        "type": "object",
        "properties": {"user_id": {"type": "string"}},
        "required": ["user_id"],
    },
    "ip_reputation": {
        "type": "object",
        "properties": {"ip_address": {"type": "string"}},
        "required": ["ip_address"],
    },
    "siem_recent_events": {
        "type": "object",
        "properties": {"user_id": {"type": "string"}},
        "required": ["user_id"],
    },
    CONTAINMENT_TOOL: {
        "type": "object",
        "properties": {
            "alert_id": {"type": "string"},
            "user_id": {"type": "string"},
            "verdict": {"type": "string", "const": "likely-compromise"},
            "authorized": {"type": "boolean"},
            "approval_required": {"type": "boolean"},
        },
        "required": [
            "alert_id",
            "user_id",
            "verdict",
            "authorized",
            "approval_required",
        ],
    },
}


def _normalize_schema(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalize_schema(item)
            for key, item in sorted(value.items())
            if key not in {"title", "description", "$schema"}
        }
    if isinstance(value, list):
        return [_normalize_schema(item) for item in value]
    return value


def validate_discovered_tools(tools: list[Any]) -> None:
    """Reject the tool server unless its inventory and schemas match the pinned copy."""
    discovered = {tool.name: tool for tool in tools}
    expected = set(PINNED_INPUT_SCHEMAS)
    unknown = set(discovered) - expected
    missing = expected - set(discovered)
    if unknown or missing:
        raise PolicyDenied(
            f"MCP tool inventory drift: unknown={sorted(unknown)}, missing={sorted(missing)}"
        )
    for name, expected_schema in PINNED_INPUT_SCHEMAS.items():
        actual = _normalize_schema(discovered[name].input_schema)
        pinned = _normalize_schema(expected_schema)
        if actual != pinned:
            raise PolicyDenied(
                f"MCP input schema drift for {name}: actual={actual}, expected={pinned}"
            )


def _validate_arguments(tool_name: str, arguments: dict[str, Any]) -> None:
    schema = PINNED_INPUT_SCHEMAS[tool_name]
    required = set(schema["required"])
    properties = set(schema["properties"])
    if set(arguments) != required or set(arguments) - properties:
        raise PolicyDenied(f"arguments do not match pinned schema for {tool_name}")
    for key, rule in schema["properties"].items():
        value = arguments[key]
        expected_type = rule["type"]
        if expected_type == "string" and not isinstance(value, str):
            raise PolicyDenied(f"{tool_name}.{key} must be a string")
        if expected_type == "boolean" and type(value) is not bool:
            raise PolicyDenied(f"{tool_name}.{key} must be a boolean")
        if "const" in rule and value != rule["const"]:
            raise PolicyDenied(f"{tool_name}.{key} violates the pinned constant")


class MCPToolBroker:
    def __init__(self, *, triage_authorized: bool, verdict: str | None = None) -> None:
        self.triage_authorized = triage_authorized
        self.verdict = verdict
        self._stack = AsyncExitStack()
        self.session: ClientSession | None = None

    async def __aenter__(self) -> Self:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "soc_triage_agent.mcp_server"],
        )
        try:
            read_stream, write_stream = await self._stack.enter_async_context(
                stdio_client(params)
            )
            self.session = await self._stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await self.session.initialize()
            inventory = await self.session.list_tools()
            validate_discovered_tools(inventory.tools)
        except BaseException:
            await self._stack.aclose()
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self._stack.aclose()

    async def call_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if tool_name not in PINNED_INPUT_SCHEMAS:
            raise PolicyDenied(f"unknown MCP tool denied: {tool_name}")
        authorize_tool_call(
            tool_name,
            triage_authorized=self.triage_authorized,
            verdict=self.verdict,
        )
        _validate_arguments(tool_name, arguments)
        if self.session is None:
            raise RuntimeError("MCP broker is not connected")
        result = await self.session.call_tool(tool_name, arguments=arguments)
        if not isinstance(result, CallToolResult):
            raise TypeError(
                f"MCP tool returned an unsupported result type: {type(result).__name__}"
            )
        if result.is_error:
            message = " ".join(getattr(item, "text", "") for item in result.content)
            raise RuntimeError(f"MCP tool {tool_name} failed: {message}")
        if not isinstance(result.structured_content, dict):
            raise TypeError(f"MCP tool {tool_name} omitted structured content")
        return sanitize_untrusted_payload(result.structured_content)


async def enrich_alert(
    alert: dict[str, Any], plan_tools: list[str], *, triage_authorized: bool
) -> dict[str, Any]:
    arguments = {
        "identity_lookup": {"user_id": alert["user_id"]},
        "signin_history": {"user_id": alert["user_id"]},
        "ip_reputation": {"ip_address": alert["source_ip"]},
        "siem_recent_events": {"user_id": alert["user_id"]},
    }
    if set(plan_tools) - READ_ONLY_TOOLS:
        raise PolicyDenied("enrichment plan contains a non-read-only tool")
    async with MCPToolBroker(triage_authorized=triage_authorized) as broker:
        results = await asyncio.gather(
            *(broker.call_tool(name, arguments[name]) for name in plan_tools)
        )
    return dict(zip(plan_tools, results, strict=True))


async def request_containment_recommendation(
    alert: dict[str, Any], verdict: str, *, triage_authorized: bool
) -> dict[str, Any]:
    async with MCPToolBroker(
        triage_authorized=triage_authorized, verdict=verdict
    ) as broker:
        return await broker.call_tool(
            CONTAINMENT_TOOL,
            {
                "alert_id": alert["alert_id"],
                "user_id": alert["user_id"],
                "verdict": verdict,
                "authorized": triage_authorized,
                "approval_required": True,
            },
        )
