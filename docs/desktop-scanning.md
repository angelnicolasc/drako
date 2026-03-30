# Desktop Agent Scanning

Drako discovers, scans, and governs AI agents installed on your machine — Claude Desktop, Cursor, VS Code, Windsurf, Claude Code, Codex CLI, Gemini CLI, and Kiro.

---

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Security Rules](#security-rules)
- [Desktop Governance](#desktop-governance)
- [Supported Clients](#supported-clients)
- [Output Formats](#output-formats)
- [CI/CD Integration](#cicd-integration)
- [Privacy](#privacy)

---

## Quick Start

```bash
drako desktop scan                    # discover + scan
drako desktop scan --format json      # machine-readable output
drako desktop bom                     # export desktop Agent BOM
drako desktop bom --format markdown   # markdown table
drako desktop govern                  # scan + activate proxy protection
```

---

## How It Works

Drako reads the configuration files of each AI client installed on your machine and extracts all declared MCP (Model Context Protocol) servers. For each server, it evaluates 8 deterministic security rules that detect misconfigurations, excessive permissions, credential exposure, and transport weaknesses.

**Discovery flow:**

1. Resolve known configuration paths for the current platform (macOS, Linux, Windows)
2. Parse each configuration file (JSON) to extract MCP server declarations
3. Classify each server's capabilities (filesystem, shell/exec, network)
4. Evaluate all 8 MCP security rules against the discovered configuration
5. Compute a Desktop Governance Score (0-100) and letter grade (A-F)

The entire process is offline and deterministic. No network requests are made during scanning.

---

## Security Rules

| Rule    | Severity | What it detects                              |
|---------|----------|----------------------------------------------|
| MCP-001 | HIGH     | Filesystem access without path restriction    |
| MCP-002 | CRITICAL | Shell/exec capability                         |
| MCP-003 | MEDIUM   | Server from unverified source                 |
| MCP-004 | MEDIUM   | Network access without domain allowlist       |
| MCP-005 | CRITICAL | Credentials stored in plaintext config        |
| MCP-006 | HIGH     | Unencrypted transport (HTTP, not HTTPS)       |
| MCP-007 | CRITICAL | Running with elevated privileges (sudo/doas)  |
| MCP-008 | HIGH     | Multiple high-risk capabilities combined      |

### Rule details

**MCP-001 — Unrestricted Filesystem Access** (HIGH)

Detects MCP servers with filesystem capabilities that lack explicit path restrictions. Without boundaries, the server can read or write any file the user has access to.

*Remediation:* Add explicit allowed paths to the server arguments.

**MCP-002 — Shell/Exec Capability** (CRITICAL)

Detects MCP servers that can execute shell commands. A compromised or malicious prompt can execute arbitrary commands on your machine through this server.

*Remediation:* Use a sandboxed execution environment or remove the server if not strictly needed. Use Drako's proxy to intercept and audit all commands.

**MCP-003 — Unverified Source** (MEDIUM)

Detects MCP servers using packages that are not from known, trusted registries (`@modelcontextprotocol/`, `@anthropic/`, `@langchain/`, `@vercel/`).

*Remediation:* Verify the package on npm/pypi. Check the source repository for security issues.

**MCP-004 — Unrestricted Network Access** (MEDIUM)

Detects MCP servers with network capabilities but no configured domain allowlist. The server could exfiltrate data to any endpoint.

*Remediation:* Configure network restrictions via Drako's proxy mode or ODD policies.

**MCP-005 — Plaintext Credentials** (CRITICAL)

Detects API keys, tokens, passwords, or other credentials stored as literal values in the configuration file instead of environment variable references.

*Remediation:* Use `${ENV_VAR}` references and set values in your shell profile or secrets manager.

**MCP-006 — Unencrypted Transport** (HIGH)

Detects SSE or HTTP-based MCP servers communicating over `http://` (not `https://`) to non-localhost endpoints. All data including prompts and tool results is transmitted in cleartext.

*Remediation:* Use HTTPS for all non-localhost MCP connections.

**MCP-007 — Elevated Privileges** (CRITICAL)

Detects MCP servers launched via `sudo`, `doas`, or `runas`, giving them elevated system privileges. A compromise of this server means full system compromise.

*Remediation:* Run MCP servers with minimum required privileges.

**MCP-008 — Multiple High-Risk Capabilities** (HIGH)

Detects MCP servers that combine two or more high-risk capabilities (filesystem + shell + network). Combined access creates a compound attack surface.

*Remediation:* Split into separate servers with single responsibilities. Use Drako's proxy to monitor each one.

---

## Desktop Governance

`drako desktop govern` goes beyond scanning. It starts the Drako proxy to intercept MCP traffic in real time:

- **ODD enforcement:** block tools outside permitted operational boundaries
- **DLP:** scan data flowing through MCP for PII and secrets
- **Circuit breaker:** trip if an MCP server exceeds action-rate limits
- **Audit trail:** log every tool call for compliance review

```bash
drako desktop govern              # default port 8990
drako desktop govern --port 9000  # custom port
```

The proxy runs until interrupted with `Ctrl+C`.

---

## Supported Clients

| Client         | Config path (macOS)                                         | Format      |
|----------------|-------------------------------------------------------------|-------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | mcpServers  |
| Claude Code    | `~/.claude.json` + `.mcp.json`                              | mcpServers  |
| Cursor         | `~/.cursor/mcp.json`                                        | mcpServers  |
| VS Code        | `~/Library/Application Support/Code/User/settings.json`     | mcp.servers |
| Windsurf       | `~/.codeium/windsurf/mcp_config.json`                       | mcpServers  |
| Codex CLI      | `~/.codex/config.json`                                      | mcpServers  |
| Gemini CLI     | `~/.gemini/settings.json`                                   | mcpServers  |
| Kiro           | `~/.kiro/mcp.json`                                          | mcpServers  |

Paths vary by operating system. Drako auto-detects the correct paths for macOS (`Darwin`), Linux, and Windows.

---

## Output Formats

### Text (default)

```
  Drako Desktop Scan
  Platform: Darwin (arm64)
  Scan time: 12ms

  Claude Desktop (/Users/you/Library/Application Support/Claude/claude_desktop_config.json)
    filesystem: @modelcontextprotocol/server-filesystem [fs]
    github: @modelcontextprotocol/server-github

  DESKTOP GOVERNANCE SCORE: 83/100 [B]
  MCP Servers: 2 total, 0 with exec, 1 with filesystem
```

### JSON

```bash
drako desktop scan --format json
```

Returns a structured JSON object with `agents`, `findings`, `summary`, `desktop_governance_score`, and `grade` fields.

### SARIF

```bash
drako desktop scan --format sarif
```

Returns SARIF 2.1.0 compliant output for integration with GitHub Code Scanning, Azure DevOps, and other SARIF-compatible tools.

---

## CI/CD Integration

Use `--fail-on` to enforce a severity threshold in CI pipelines:

```bash
# Fail if any CRITICAL or HIGH findings
drako desktop scan --fail-on high --format sarif > desktop-scan.sarif
```

Exit codes:
- `0` — no findings at or above the threshold
- `1` — at least one finding at or above the threshold

### GitHub Actions example

```yaml
- name: Scan desktop agents
  run: drako desktop scan --fail-on high --format sarif > desktop.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: desktop.sarif
```

---

## Privacy

Desktop scanning is **100% local**. No data leaves your machine. No backend connection is required. No telemetry is collected from desktop scans. All rule evaluation is deterministic and offline.
