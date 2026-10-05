# Changelog

## [Unreleased]

## [0.2.0] - 2026-10-05

### Fixed
- A scalar `servers:`/`tools:` in the deny policy is no longer iterated per
  character: `servers: acme-notes` became `['a', 'c', 'm', 'e', '-', 'n', 'o',
  't', 'e', 's']`, so the rule matched nothing and the scan exited 0, while
  `servers: acme-*` left a bare `*` that denied every server; a non-mapping
  policy document now raises a clean error instead of a raw `AttributeError`
  (#96)
- `auth` given as an object is no longer read as authenticated because the
  object is truthy: `{"required": false}`, `{"enabled": false}`,
  `{"type": "none"}` and OpenAPI `"security": [{"none": []}]` now resolve to the
  same "disabled" state as the scalar `"auth": false`, so MCP002 (and MCP001,
  MCP007, MCP009) stop silently skipping an unauthenticated destructive tool
  that declares it in object form. Both detectors read one shared tri-state, so
  a genuinely authenticated tool stays unflagged (#94)
- A malformed auto-discovered `mcp-guard.yaml`/`mcp-guard.yml` is now a hard
  error (exit 1) instead of being silently skipped: the scan used to run with
  an empty deny policy, so a server the policy named passed as clean and
  `--deny` still exited 0 (#83)
- `permissions` and `auth.scopes` accept a scalar string, a list, or nothing:
  a bare string was iterated per character, so `"admin:write"` became 11
  permissions and a spurious MCP003 finding; a non-list value raised a bare
  `TypeError` (#85)
- Description matching honours the same leading-read-verb gate as name
  matching: `list_commands`, `get_command_history`, `help` and `readme` no
  longer flag as command execution (nor `get_updates` as a write) purely for
  mentioning the noun, while descriptions that act ("Deletes all records",
  "Read the record and delete it") still match (#91)
- A read verb in the first sentence no longer gates a destructive or write
  operation in a later one: "Get the current token. Drop the table when done",
  "Show settings; clear the cache when full" and "Get the record. Update its
  owner" were silently unflagged because the gate only read the text before
  the first keyword hit, so a read-only prefix swallowed a later sentence
  entirely; read-only descriptions such as "Return the command history" stay
  unflagged (#95)
- `scan --fail-on low` no longer exits 1 on a zero-findings scan: an empty
  result now reads as below every threshold, so the lowest gate works as a
  "fail on anything at all" CI tripwire (#82)
- Write/destructive keyword classification now matches whole identifier segments
  and word boundaries: read-only names like `get_address`, `read_settings`,
  `get_clear_status` or `search_update_records` (and descriptions mentioning
  `created`/`settings`/`input`) no longer produce MCP001/MCP002/MCP006
  findings against safe servers, while `delete_repo`, `clear_cache`,
  `update_records`, camelCase and kebab-case names still match (#84)

### Added
- `MCP009` command execution detection: a third classification dimension
  (`is_command_execution`) for capabilities that run arbitrary code or spawn
  processes (`exec`, `execute`, `eval`, `spawn`, `shell`, `bash`, `cmd`,
  `command`, `subprocess`, `popen`, `terminal` — whole identifier segments with
  the same read-verb suppression and description inflection matching as
  MCP001/MCP002, so `get_exec_summary` stays unflagged). `MCP009` fires at HIGH
  when such a capability has no authentication, with message text that says the
  tool executes commands rather than "performs write operations". It is
  intentionally not coupled into MCP005/MCP006/MCP007: a shell tool has no
  meaningful "corresponding read" (#89)
- `MCP008` prompt injection detection for server and capability metadata, including
  every `inputSchema` key and string value, with SARIF/JSON classification properties
- `--strict-injection` flag and optional `canary` extra that add Little Canary's
  structural filter (no model or network calls)
- `mcp-guard verify` command and `supply_chain` module: npm supply chain
  verification via sigstore attestations / SLSA provenance, with
  `--policy strict` enforcement and JSON output (stdlib-only, offline tests)
- Initial release
