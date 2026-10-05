"""Deny rules policy for MCP Guard."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import BaseModel, Field

from .models import MCPManifest, RiskFinding, RiskLevel
from .parser import as_permission_list


class DenyPolicy(BaseModel):
    """Policy defining denied MCP servers and tools."""

    servers: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)

    @classmethod
    def from_yaml(cls, source: str | Path) -> DenyPolicy:
        """Load deny policy from a YAML file path or YAML content string.

        Preserves compatibility with comments and documentation in YAML files.
        """
        content: str
        if isinstance(source, Path):
            content = source.read_text(encoding="utf-8")
        elif "\n" not in source and len(source) < 1024 and Path(source).is_file():
            content = Path(source).read_text(encoding="utf-8")
        else:
            content = source

        parsed: object = yaml.safe_load(content) or {}
        deny_block: object = parsed
        if isinstance(parsed, dict):
            deny_block = cast("dict[str, Any]", parsed).get("deny", parsed)
        if not isinstance(deny_block, dict):
            # A bare list/scalar document, or a scalar `deny:` value, is not a
            # mapping; calling .get on it raised a raw AttributeError instead of
            # a clean config error.
            raise ValueError(
                f"Policy must be a YAML mapping with an optional 'deny' block, "
                f"got {type(deny_block).__name__}"
            )
        block: dict[str, Any] = cast("dict[str, Any]", deny_block)

        # A scalar `servers:`/`tools:` is valid YAML; list-comprehending it
        # iterated it per character, so the rule matched nothing and a wildcard
        # policy left a bare '*' that denied every server (#96).
        servers = as_permission_list(block.get("servers"))
        tools = as_permission_list(block.get("tools"))

        return cls(servers=servers, tools=tools)

    def is_server_denied(self, server_name: str) -> tuple[bool, str | None]:
        """Check if a server matches any deny pattern.

        Supports exact matches and wildcard patterns (e.g. 'github-*').
        Returns (is_denied, matched_pattern).
        """
        for pattern in self.servers:
            if fnmatch.fnmatch(server_name, pattern):
                return True, pattern
        return False, None

    def is_tool_denied(
        self, tool_name: str, server_name: str | None = None
    ) -> tuple[bool, str | None]:
        """Check if a tool matches any deny pattern.

        Supports:
        - Exact tool matches: e.g. 'delete_repo'
        - Wildcard tool matches: e.g. 'delete_*'
        - Server-scoped tool matches: e.g. 'github/delete_repo' or 'github-*/write'

        Returns (is_denied, matched_pattern).
        """
        for pattern in self.tools:
            # Direct match on tool name (exact or wildcard)
            if fnmatch.fnmatch(tool_name, pattern):
                return True, pattern

            if server_name:
                qualified = f"{server_name}/{tool_name}"
                if fnmatch.fnmatch(qualified, pattern):
                    return True, pattern

                # Check server/tool split pattern e.g. "github-*/delete_*"
                if "/" in pattern:
                    srv_pat, tool_pat = pattern.split("/", 1)
                    if fnmatch.fnmatch(server_name, srv_pat) and fnmatch.fnmatch(
                        tool_name, tool_pat
                    ):
                        return True, pattern

        return False, None

    def check_manifest(self, manifest: MCPManifest) -> list[RiskFinding]:
        """Evaluate manifest against deny rules and return critical risk findings."""
        findings: list[RiskFinding] = []

        # Server-level check
        server_denied, matched_srv_pattern = self.is_server_denied(manifest.name)
        if server_denied:
            findings.append(
                RiskFinding(
                    rule_id="DENY001",
                    level=RiskLevel.CRITICAL,
                    message=f"Server '{manifest.name}' matches deny rule: '{matched_srv_pattern}'",
                    capability_name=manifest.name,
                    suggestion="Remove or replace this server as it is blocked by security policy",
                )
            )

        # Tool-level checks
        for cap in manifest.capabilities:
            tool_denied, matched_tool_pattern = self.is_tool_denied(
                cap.name, server_name=manifest.name
            )
            if tool_denied:
                findings.append(
                    RiskFinding(
                        rule_id="DENY002",
                        level=RiskLevel.CRITICAL,
                        message=f"Tool '{cap.name}' matches deny rule: '{matched_tool_pattern}'",
                        capability_name=cap.name,
                        capability_type=cap.type,
                        suggestion="Remove or disable this capability (blocked by security policy)",
                    )
                )

        return findings
