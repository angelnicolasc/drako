# Runtime Capabilities

> The scan tells you what's wrong. The platform fixes it — and keeps it fixed.

Drako's runtime sits between your agents and the world. Every tool call, every inter-agent message, every action passes through an enforcement pipeline before it executes. No agent bypasses it. No exception.

---

## Enforcement Pipeline

When an agent decides to act, the decision travels through this chain. Any step can block, modify, or escalate — before a single byte reaches your downstream APIs.

```
Agent decides to act
  │
  ├─ Pre-action Hooks ─── custom validation scripts
  ├─ Identity Check ───── is this agent who it claims to be?
  ├─ ODD Check ────────── is this tool permitted for this agent?
  ├─ Magnitude Check ──── does this exceed spend/volume/scope limits?
  ├─ HITL Check ───────── does this need human approval?
  ├─ Intent Gate 1 ────── fingerprint the decision (SHA-256 + Ed25519)
  ├─ DLP Scan ─────────── does the payload contain PII/PCI?
  ├─ Injection Scan ───── does the input contain prompt injection?
  ├─ Trust Check ──────── is this agent's reputation sufficient?
  ├─ IOC Check ────────── does this match a known threat pattern?
  ├─ Circuit Breaker ──── is this tool/agent healthy enough?
  ├─ Intent Gate 2 ────── verify the decision wasn't altered since Gate 1
  │
  ▼
  Execute (or block with reason)
  │
  ├─ Post-action Hooks ── validate/modify result
  ├─ Topology Tracker ─── log interaction for multi-agent graph
  ├─ Cost Tracker ─────── record tokens, cost, model used
  └─ Audit Trail ──────── SHA-256 hash chain + policy snapshot ID
```

---

## Capabilities

### 🔒 Security & Trust

**DLP (Data Loss Prevention)**
Presidio-based PII/PCI detection runs on every tool call payload. If the payload contains critical PII, the action is rejected before it reaches any downstream API.

**Prompt Injection Detection**
Bidirectional scanning: catches injection attempts in external data reaching your agents — documents, API responses, tool results. Five deterministic pattern categories. No LLM involved. Complements DLP, which scans outputs.

**Agent Identity**
Managed credential lifecycle per agent: dynamic provisioning, automatic rotation with grace periods, and instant revocation. DID-based. No more shared static API keys spread across agents.

**Trust Score**
Per-agent EigenTrust reputation score (0–100), updated on every interaction and time-decayed. Agents earn or lose trust based on actual behavior — not just configuration.

**Intent Fingerprinting**
Two-gate cryptographic verification (SHA-256 + Ed25519). Gate 1 fingerprints the decision at the moment it's made. Gate 2 verifies nothing changed before execution. If a hallucination or injection alters the action in between — it's blocked. Every verification produces SOC 2-ready audit proof.

**Collective Intelligence**
When one agent detects a threat, every agent benefits. Anonymous IOC (Indicator of Compromise) sharing across tenants. Six AI-native IOC types. EigenTrust quality scoring. Sub-5s propagation. One detection in São Paulo protects a deployment in Berlin.

---

### ⚙️ Control & Governance

**ODD Enforcement (Operational Design Domain)**
Declare exactly which tools, APIs, data sources, and time windows each agent is allowed to operate in. Allowlisting, not denylisting. Three modes: `audit`, `enforce`, `escalate`.

**Magnitude Limits**
Pre-action guardrails: spend caps per action/session/day, data volume limits, blast radius constraints, compute guardrails. All evaluated and enforced before execution.

**Human-in-the-Loop (HITL)**
Agents pause on high-risk actions and escalate to a human supervisor. Configurable triggers: tool type, trust threshold, spend amount, first-time actions. Webhook notifications via Slack, Teams, or email. EU AI Act Article 14 compliant.

**Circuit Breaker**
Per-agent and per-tool. If one tool fails repeatedly, that tool auto-suspends — the agent keeps running with everything else. Hierarchy: tool CB → agent CB → fleet halt. When a CB trips, operations don't die: they failover to deterministic code, a simpler agent, a human operator, or a retry queue. State is preserved.

**Programmable Hooks**
Python scripts or YAML conditions that run at `pre_action`, `post_action`, `on_error`, and `on_session_end`. Stop hooks can block session completion until all checks pass.

**Context Versioning**
Every config push creates an immutable SHA-256 snapshot. Audit logs reference the exact policy version active at the time of every action. Diff, rollback, and full change history included.

---

### 🕸️ Multi-Agent

**Secure A2A**
Agent-to-agent communication is routed through the governance gateway. Mutual authentication via DID exchange, channel policies controlling who talks to whom, injection scanning on inter-agent messages, and propagation depth limits to prevent prompt worm spread.

**Multi-Agent Topology**
Live directed graph of agent interactions. Detects resource contention, contradictory actions, cascade amplification, and circular dependencies. Fleet Health Score (0–100) always visible.

**Chaos Engineering**
Controlled fault injection for resilience testing: deny tools, inject latency, expire credentials, exhaust budgets, disconnect peers. Governance Grade (A–F) based on how the fleet responds. Safety-gated via HITL approval.

---

### 📊 Observability & FinOps

**Observability**
Session traces with full span trees, latency breakdowns (P50/P95/P99), violation heatmaps, drift detection from intent fingerprint mismatches, loop detection, quality scoring, and A/B testing between policy versions.

**Alerting**
Configurable rules in YAML. Deliver to Slack, email, or PagerDuty. Example rules: `drift rate > 5%`, `daily spend > $100`, `injection events > 10/hour`.

**FinOps**
Cost-per-outcome tracking, smart model routing (route simple tasks to cheaper models), semantic caching (skip LLM calls for repeated queries), and budget alerts at 50/80/95%. The dashboard shows exactly how much Drako saved you.

**OTEL & SIEM Export**
Pipe traces to Datadog, Grafana, or New Relic via OpenTelemetry. Export security events to Splunk or ELK via STIX 2.1 or CEF.

**Audit Trail**
SHA-256 hash chain with Ed25519 signatures. Every action logged with cryptographic integrity, policy snapshot reference, and intent proof. Tamper-evident, exportable, and regulator-ready.

**Compliance Reports**
Generated from real scan data and runtime telemetry. Covers EU AI Act Articles 9, 11, 12, and 14. Exportable for auditors and regulators.

---

## Supported Frameworks

Drako integrates with the frameworks your agents already run on. Detection is automatic.

| Framework | Integration method |
|---|---|
| LangGraph | AST-based discovery |
| CrewAI | AST-based discovery |
| AutoGen | AST-based discovery |
| LangChain | Import / pattern detection |
| LlamaIndex | Import / pattern detection |
| PydanticAI | Import / pattern detection |

