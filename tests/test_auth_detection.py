"""Tests for authentication detection and falsy bypass prevention (Issue #41)."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_guard.formatters import to_dict, to_sarif
from mcp_guard.models import MCPCapability, MCPCapabilityType, RiskLevel
from mcp_guard.parser import MCPParser
from mcp_guard.rules import (
    ExplicitlyDisabledAuthRule,
)
from mcp_guard.scanner import Scanner


def _resolve(data: dict[str, Any]) -> str:
    """Read the tri-state normalizer, or derive it from the two callers.

    The fallback keeps these tests discriminating on behaviour rather than on
    the existence of `_resolve_auth`, so a regression is a failed assertion
    and not an AttributeError.
    """
    normalize = getattr(MCPParser, "_resolve_auth", None)
    if normalize is not None:
        return str(normalize(data))
    if MCPParser._detect_auth(data):
        return "enabled"
    if MCPParser._detect_auth_disabled(data):
        return "disabled"
    return "unknown"


class TestDetectAuth:
    """Unit tests for _detect_auth and _detect_auth_disabled in MCPParser."""

    def test_auth_true(self):
        data = {"name": "test_tool", "auth": True}
        assert MCPParser._detect_auth(data) is True
        assert MCPParser._detect_auth_disabled(data) is False

    def test_auth_dict_truthy(self):
        data = {"name": "test_tool", "auth": {"type": "oauth2", "scopes": ["read"]}}
        assert MCPParser._detect_auth(data) is True
        assert MCPParser._detect_auth_disabled(data) is False

    def test_auth_false_disabled(self):
        """'auth': False must NOT be detected as authenticated; must be flagged disabled."""
        data = {"name": "test_tool", "auth": False}
        assert MCPParser._detect_auth(data) is False
        assert MCPParser._detect_auth_disabled(data) is True

    def test_auth_null(self):
        """'auth': None must NOT be detected as authenticated."""
        data = {"name": "test_tool", "auth": None}
        assert MCPParser._detect_auth(data) is False
        assert MCPParser._detect_auth_disabled(data) is False

    def test_auth_empty_dict(self):
        """'auth': {} has no config; must not be detected as authenticated."""
        data = {"name": "test_tool", "auth": {}}
        assert MCPParser._detect_auth(data) is False
        assert MCPParser._detect_auth_disabled(data) is False

    def test_auth_zero_and_empty_string(self):
        """Falsy integers or strings must not be detected as authenticated."""
        assert MCPParser._detect_auth({"auth": 0}) is False
        assert MCPParser._detect_auth({"auth": ""}) is False

    def test_auth_key_not_present(self):
        """Absent auth key is neither authenticated nor explicitly disabled."""
        data = {"name": "test_tool"}
        assert MCPParser._detect_auth(data) is False
        assert MCPParser._detect_auth_disabled(data) is False

    def test_authorization_variants(self):
        """Checks 'authorization' key with truthy and falsy values."""
        assert MCPParser._detect_auth({"authorization": True}) is True
        assert MCPParser._detect_auth({"authorization": {"type": "apiKey"}}) is True
        assert MCPParser._detect_auth({"authorization": False}) is False
        assert MCPParser._detect_auth_disabled({"authorization": False}) is True

    def test_security_openapi_variant(self):
        """Checks OpenAPI-style 'security' property."""
        assert MCPParser._detect_auth({"security": [{"apiKey": []}]}) is True
        assert MCPParser._detect_auth({"security": []}) is False
        assert MCPParser._detect_auth({"security": None}) is False


class TestObjectShapedAuthDisabling:
    """#94: `auth` as an object is never falsy, so its disabling body was ignored.

    A tool declaring no authentication inside `{"required": false}` (or any
    other disabling shape) must resolve to the same tri-state as the scalar
    form, so MCP002/MCP001/MCP007/MCP009 stop silently skipping it.
    """

    @pytest.mark.parametrize(
        "field",
        [
            {"auth": {"required": False}},
            {"auth": {"required": "false"}},
            {"auth": {"enabled": False}},
            {"auth": {"enabled": "off"}},
            {"auth": {"type": "none"}},
            {"auth": {"type": "NONE", "scopes": []}},
            {"authorization": {"required": False}},
            {"security": [{"none": []}]},
        ],
    )
    def test_disabling_shapes_resolve_disabled(self, field):
        assert _resolve(field) == "disabled"
        assert MCPParser._detect_auth(field) is False
        assert MCPParser._detect_auth_disabled(field) is True

    @pytest.mark.parametrize(
        "field",
        [
            {"auth": {"required": True}},
            {"auth": {"enabled": True, "type": "apiKey"}},
            {"auth": {"type": "oauth2", "scopes": ["read"]}},
            {"auth": {"type": "bearer"}},
        ],
    )
    def test_enabled_shapes_stay_enabled(self, field):
        """Negative control: a genuinely authenticated tool stays authenticated."""
        assert _resolve(field) == "enabled"
        assert MCPParser._detect_auth(field) is True
        assert MCPParser._detect_auth_disabled(field) is False

    def test_empty_object_stays_unknown(self):
        """An empty object says nothing; it must not become an explicit disable."""
        assert _resolve({"auth": {}}) == "unknown"
        assert MCPParser._detect_auth({"auth": {}}) is False
        assert MCPParser._detect_auth_disabled({"auth": {}}) is False

    def test_destructive_object_auth_triggers_rules(self):
        """The issue's manifest: MCP002 and MCP007 must both be reported."""
        manifest = MCPParser.from_dict(
            {
                "name": "demo",
                "version": "1.0.0",
                "tools": [
                    {
                        "name": "delete_all_records",
                        "description": "Delete every record from the datastore.",
                        "auth": {"required": False},
                    }
                ],
                "resources": [],
                "prompts": [],
            }
        )
        cap = manifest.capabilities[0]
        assert cap.has_auth is False
        assert cap.auth_disabled is True
        assert cap.auth_status == "disabled"

        result = Scanner().scan(manifest)
        rule_ids = sorted(f.rule_id for f in result.findings)
        assert "MCP002" in rule_ids
        assert "MCP007" in rule_ids
        assert result.risk_score == RiskLevel.CRITICAL

    def test_write_and_exec_object_auth_trigger_rules(self):
        """MCP001 and MCP009 read the same field and must see the same decision."""
        for tool, expected in (
            (
                {
                    "name": "write_config_file",
                    "description": "Write system config",
                    "auth": {"enabled": False},
                },
                "MCP001",
            ),
            (
                {
                    "name": "run_shell_command",
                    "description": "Execute an arbitrary shell command on the host",
                    "auth": {"type": "none"},
                },
                "MCP009",
            ),
        ):
            manifest = MCPParser.from_dict({"name": "demo", "tools": [tool]})
            assert manifest.capabilities[0].has_auth is False
            rule_ids = sorted(f.rule_id for f in Scanner().scan(manifest).findings)
            assert expected in rule_ids

    def test_security_none_alongside_enabled_auth_stays_authenticated(self):
        """`security` says nothing when auth is explicitly on; enabled wins."""
        data = {"auth": "bearer-token", "security": [{"none": []}]}
        assert _resolve(data) == "enabled"
        assert MCPParser._detect_auth(data) is True
        assert MCPParser._detect_auth_disabled(data) is False


class TestCapabilityAuthStatus:
    """Test MCPCapability model properties and auth status evaluation."""

    def test_auth_status_required(self):
        cap = MCPCapability(name="tool", type=MCPCapabilityType.TOOL, has_auth=True)
        assert cap.auth_status == "required"

    def test_auth_status_disabled(self):
        cap = MCPCapability(name="tool", type=MCPCapabilityType.TOOL, auth_disabled=True)
        assert cap.auth_status == "disabled"

    def test_auth_status_unknown(self):
        cap = MCPCapability(name="tool", type=MCPCapabilityType.TOOL)
        assert cap.auth_status == "unknown"


class TestFalsyAuthBypassPrevention:
    """Verify malicious servers cannot bypass write/destructive security rules using falsy auth."""

    def test_destructive_with_auth_false_triggers_rules(self):
        """Setting 'auth': false on destructive tool must trigger MCP002 and MCP007."""
        manifest_data = {
            "name": "malicious-server",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "delete_all_records",
                    "description": "Delete database records",
                    "auth": False,
                    "inputSchema": {
                        "type": "object",
                        "properties": {"confirm": {"type": "boolean"}},
                    },
                },
            ],
        }
        manifest = MCPParser.from_dict(manifest_data)
        cap = manifest.capabilities[0]
        assert cap.has_auth is False
        assert cap.auth_disabled is True
        assert cap.auth_status == "disabled"

        scanner = Scanner()
        result = scanner.scan(manifest)

        rule_ids = [f.rule_id for f in result.findings]
        # MCP002: Unauthenticated destructive
        assert "MCP002" in rule_ids
        # MCP007: Explicitly disabled auth
        assert "MCP007" in rule_ids
        assert result.risk_score == RiskLevel.CRITICAL

    def test_write_with_auth_null_triggers_mcp001(self):
        """Setting 'auth': null on write tool must trigger MCP001."""
        manifest_data = {
            "name": "unauthenticated-server",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "write_config_file",
                    "description": "Write system config",
                    "auth": None,
                },
            ],
        }
        manifest = MCPParser.from_dict(manifest_data)
        cap = manifest.capabilities[0]
        assert cap.has_auth is False
        assert cap.auth_disabled is False
        assert cap.auth_status == "unknown"

        scanner = Scanner()
        result = scanner.scan(manifest)

        rule_ids = [f.rule_id for f in result.findings]
        assert "MCP001" in rule_ids

    def test_write_with_auth_empty_dict_triggers_mcp001(self):
        """Setting 'auth': {} on write tool must trigger MCP001."""
        manifest_data = {
            "name": "unauthenticated-server",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "update_user_record",
                    "description": "Update user record",
                    "auth": {},
                },
            ],
        }
        manifest = MCPParser.from_dict(manifest_data)
        cap = manifest.capabilities[0]
        assert cap.has_auth is False
        assert cap.auth_disabled is False

        scanner = Scanner()
        result = scanner.scan(manifest)

        rule_ids = [f.rule_id for f in result.findings]
        assert "MCP001" in rule_ids


class TestExplicitlyDisabledAuthRule:
    """Direct tests for ExplicitlyDisabledAuthRule (MCP007)."""

    def test_mcp007_destructive_level_critical(self):
        rule = ExplicitlyDisabledAuthRule()
        manifest_data = {"name": "srv"}
        manifest = MCPParser.from_dict(manifest_data)
        cap = MCPCapability(
            name="purge_cache",
            type=MCPCapabilityType.TOOL,
            auth_disabled=True,
            is_destructive=True,
        )
        findings = rule.check(cap, manifest)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP007"
        assert findings[0].level == RiskLevel.CRITICAL

    def test_mcp007_write_level_high(self):
        rule = ExplicitlyDisabledAuthRule()
        manifest_data = {"name": "srv"}
        manifest = MCPParser.from_dict(manifest_data)
        cap = MCPCapability(
            name="create_log",
            type=MCPCapabilityType.TOOL,
            auth_disabled=True,
            is_write=True,
        )
        findings = rule.check(cap, manifest)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP007"
        assert findings[0].level == RiskLevel.HIGH

    def test_mcp007_read_level_medium(self):
        rule = ExplicitlyDisabledAuthRule()
        manifest_data = {"name": "srv"}
        manifest = MCPParser.from_dict(manifest_data)
        cap = MCPCapability(
            name="get_stats",
            type=MCPCapabilityType.TOOL,
            auth_disabled=True,
        )
        findings = rule.check(cap, manifest)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP007"
        assert findings[0].level == RiskLevel.MEDIUM

    def test_mcp007_no_findings_when_not_disabled(self):
        rule = ExplicitlyDisabledAuthRule()
        manifest_data = {"name": "srv"}
        manifest = MCPParser.from_dict(manifest_data)
        cap = MCPCapability(name="safe_tool", type=MCPCapabilityType.TOOL, auth_disabled=False)
        assert rule.check(cap, manifest) == []


class TestSARIFAuthOutput:
    """Verify SARIF 2.1.0 output includes auth status property."""

    def test_sarif_includes_auth_status(self):
        manifest_data = {
            "name": "sarif-auth-server",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "delete_all",
                    "description": "Delete all data",
                    "auth": False,
                },
                {
                    "name": "write_data",
                    "description": "Write system data",
                    "auth": None,
                },
            ],
        }
        manifest = MCPParser.from_dict(manifest_data)
        scanner = Scanner()
        result = scanner.scan(manifest)

        sarif = to_sarif(result)
        results = sarif["runs"][0]["results"]
        assert len(results) > 0

        # delete_all findings must have auth_status == "disabled"
        delete_results = [
            r
            for r in results
            if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "mcp-server/delete_all"
        ]
        assert len(delete_results) > 0
        for r in delete_results:
            assert "properties" in r
            assert r["properties"]["auth_status"] == "disabled"

        # write_data findings must have auth_status == "unknown"
        write_results = [
            r
            for r in results
            if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "mcp-server/write_data"
        ]
        assert len(write_results) > 0
        for r in write_results:
            assert "properties" in r
            assert r["properties"]["auth_status"] == "unknown"


class TestSummaryAuthBreakdown:
    """Verify scan summary contains auth metrics."""

    def test_summary_auth_metrics(self):
        manifest_data = {
            "name": "summary-server",
            "version": "1.0.0",
            "tools": [
                {"name": "authed_tool", "auth": True},
                {"name": "disabled_tool", "auth": False},
                {"name": "unspecified_tool"},
            ],
        }
        manifest = MCPParser.from_dict(manifest_data)
        scanner = Scanner()
        result = scanner.scan(manifest)

        assert result.summary["auth_required"] == 1
        assert result.summary["auth_disabled"] == 1
        assert result.summary["auth_none"] == 1

        as_dict = to_dict(result)
        assert as_dict["summary"]["auth_required"] == 1
        assert as_dict["summary"]["auth_disabled"] == 1
        assert as_dict["summary"]["auth_none"] == 1
