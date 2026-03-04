# AgentMesh

**Scan your AI agents for governance gaps. Enforce policies in production.**

[![PyPI version](https://badge.fury.io/py/agentmesh.svg)](https://badge.fury.io/py/agentmesh)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests passing](https://img.shields.io/badge/tests-538%20passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](https://mariadb.com/bsl11/)
[![Policy Eval](https://img.shields.io/badge/policy%20eval-<2ms-brightgreen.svg)]()

---

## What is AgentMesh?

AgentMesh is a governance platform for AI agents, built in two layers:

1. **Scan CLI (free, offline, no account)** — Analyzes your codebase via AST to find governance gaps, generate an Agent BOM, and map EU AI Act requirements. Like `snyk test` for AI agents.
2. **Runtime Platform (SaaS, requires account)** — Middleware that intercepts tool calls in production to enforce policies, scan payloads for PII, and track agent trust. Like `snyk monitor` for AI agents.

---

## Quick Start

```bash
pip install useagentmesh
agentmesh scan .
# → Governance Score: 35/100 | 8 findings | Agent BOM: 3 agents, 12 tools
# → Run `agentmesh auth login` to enable runtime governance
```

### MCP Server (Claude Desktop)
Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "agentmesh": {
      "command": "uvx",
      "args": ["agentmesh-mcp"],
      "env": {
        "AGENTMESH_API_KEY": "your-api-key"
      }
    }
  }
}
```

### MCP Server (VS Code / Cursor)
Add to MCP settings:
```json
{
  "mcp": {
    "servers": {
      "agentmesh": {
        "command": "uvx",
        "args": ["agentmesh-mcp"]
      }
    }
  }
}
```

---

## What You Get Free (Scan CLI)

* 🔍 **Governance Score**: 0-100 score based on 33 deterministic policy rules (<2ms evaluation)
* 📦 **Agent BOM**: AST-based inventory of agents, tools, and models in your project
* 🛠️ **Fix Snippets**: Actionable remediation for every finding
* 📄 **SARIF 2.1.0**: Native GitHub Code Scanning integration
* 🇪🇺 **EU AI Act Gaps**: Detects non-compliance with Art. 9, 11, 12, 14

### Supported Frameworks

| Framework | Supported | Discovery |
|---|:---:|:---:|
| **LangGraph** | ✅ | AST-based |
| **CrewAI** | ✅ | AST-based |
| **AutoGen** | ✅ | AST-based |
| **LangChain** | ✅ | Standard |
| **LlamaIndex** | ✅ | Standard |
| **Pydantic AI** | ✅ | Standard |

### Output Formats

* **SARIF 2.1.0** (GitHub Code Scanning compatible)
* **JSON** (For CI/CD integrations)
* **SVG Badges** (For repository docs)

### Benchmark Results

All measurements taken with `time.perf_counter_ns()`, 10,000 iterations after 1,000 warmup. [Methodology & reproduction →](benchmarks/README.md)

**Policy Engine** (33 deterministic rules, zero LLMs):

| Scenario | P50 | P99 |
|---|---|---|
| Single rule evaluation | **0.031ms** | 0.08ms |
| Full scan (33 rules) | **1.84ms** | 3.2ms |
| Batch (100 tool calls) | **1.79ms** | 2.8ms |

> Governance overhead is **<0.2%** of a typical LLM call (~800ms).

**AST Framework Discovery:**

| Framework | Avg Latency |
|---|---|
| CrewAI | ~5ms |
| LangGraph | ~7ms |
| AutoGen | ~9ms |

---

## Runtime Governance (SaaS Platform)

When you connect the SDK to the AgentMesh platform, you unlock runtime governance features that protect your agents **in production**:

* 🔐 **DLP Runtime** — Presidio-based PII/PCI scanning on tool call payloads before they hit downstream APIs
* 📊 **Dynamic Trust Score** — 0-100 EigenTrust score per agent, updated on every interaction
* ⚡ **Circuit Breaker** — Auto-suspends agents when Trust Score drops below threshold
* 🔐 **Cryptographic Audit Trail** — SHA-256 hash chain + Ed25519 digital signatures (non-repudiation)
* 👥 **RBAC + Teams** — Multi-user access control per organization
* 📋 **EU AI Act Reports** — Exportable compliance reports for regulators

### PRO Tier — Advanced Agent Controls

* 🧭 **Operational Design Domain (ODD)** — Define permitted tools, rate limits, and cost caps per agent. Enforcement modes: audit, enforce, escalate
* 📏 **Pre-Action Magnitude Limits** — Pre-trade risk controls for AI agents: financial spend caps, data volume limits, blast radius constraints, and compute guardrails — validated before every action executes
* 🪪 **Agent Identity Management** — Managed credential lifecycle for non-human identities: DID provisioning, auto-rotation with grace periods, instant revocation, and ephemeral JWT support

> These features require an account. [Sign up free →](https://useagentmesh.com)

---

## How We Compare

| Feature | AgentMesh Scan (free) | AgentMesh Platform (SaaS) | Bifrost | Cordum |
|---|:---:|:---:|:---:|:---:|
| **Language** | Python | Python | Go | Go |
| **Static Governance Score** | ✅ | ✅ | ❌ | ❌ |
| **Agent BOM (AST)** | ✅ | ✅ | ❌ | ❌ |
| **SARIF Output** | ✅ | ✅ | ❌ | ❌ |
| **EU AI Act Gap Detection** | ✅ | ✅ | ❌ | ❌ |
| **DLP Runtime (Presidio)** | — | ✅ | ❌ | ❌ |
| **Dynamic Trust Score** | — | ✅ | ❌ | ❌ |
| **Cryptographic Audit Trail** | — | ✅ | ❌ | ❌ |
| **Circuit Breaker** | — | ✅ | ❌ | ❌ |
| **ODD Enforcement** | — | ✅ (PRO) | ❌ | ❌ |
| **Pre-Action Magnitude Limits** | — | ✅ (PRO) | ❌ | ❌ |
| **Agent Identity Management** | — | ✅ (PRO) | ❌ | ❌ |

---

## Pricing

| Tier | Price | Tasks/month | What you get |
|---|---|---|---|
| **Free (no account)** | $0 | — | Scan CLI, Agent BOM, SARIF, findings |
| **Free (with account)** | $0 | 10,000 | + Runtime middleware, basic audit trail |
| **Starter** | $29 | 50,000 | + DLP runtime (Presidio) |
| **Pro** | $49 | 200,000 | + ODD, Magnitude Limits, Agent Identity, Trust Score, Circuit Breaker |
| **Team** | $199 | 500,000 | + SSO, 365-day retention, 25 team members |
| **Enterprise** | Custom | Unlimited | Everything in Pro + BFT consensus, custom SLA, dedicated support |

🔗 [View Pricing Plans](https://useagentmesh.com/pricing)

---

## Links & Resources

* 📜 **Documentation**: [docs.useagentmesh.com](https://docs.useagentmesh.com)
* 🌐 **Landing Page**: [useagentmesh.com](https://useagentmesh.com)
* 🧩 **MCP Server**: [Coming via Smithery/PulseMCP](#)

---

<p align="center">
  <b>AgentMesh</b> — Governance for AI Agents
</p>
