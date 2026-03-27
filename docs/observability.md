# Observability in Drako

Drako provides **full-stack observability** for AI agent fleets. From latency percentiles to violation heatmaps, from cost-per-model tracking to real-time drift detection — everything is built in.

No Grafana setup. No Prometheus configuration. No external tooling to manage. Just connect your agents and open the dashboard.

---

## Table of Contents

- [Architecture](#architecture)
- [Dashboard Overview](#dashboard-overview)
- [Observability Page](#observability-page)
  - [Health Overview](#health-overview)
  - [Metrics](#metrics)
  - [Violations](#violations)
  - [Alerts](#alerts)
- [FinOps](#finops)
- [Real-Time Updates](#real-time-updates)
- [Metrics Reference](#metrics-reference)
- [Plan Availability](#plan-availability)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                             YOUR AGENT FLEET                             │
│     [ agent-1 ]     [ agent-2 ]     [ agent-3 ]      [ agent-n ]         │
└──────────┬───────────────┬───────────────┬───────────────┬───────────────┘
           │               │               │               │
           ▼               ▼               ▼               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                      DRAKO SDK (pip install drako)                       │
│        Trust Evaluation  •  Policy Enforcement  •  Audit Logging         │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                        HTTPS / WSS / mTLS
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         DRAKO BACKEND (FastAPI)                          │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Trust Engine │  │ Audit Chain  │  │ Policy Eng.  │  │   Metering   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Observ. Svc  │  │  FinOps Svc  │  │  Alert Svc   │  │  OTEL Exp.   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ Prometheus Metrics (/metrics) + Custom Business Instrumentation    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────┐    ┌────────────┐    ┌─────────────┐    ┌────────────┐   │
│  │  Postgres  │    │   Redis    │    │Grafana Alloy│    │  WS Hub    │   │
│  │   (RLS)    │    │  (Cache)   │    │ (Collector) │    │(Real-time) │   │
│  └────────────┘    └────────────┘    └─────────────┘    └────────────┘   │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         DRAKO DASHBOARD (React)                          │
│                          getdrako.com/dashboard                          │
│                                                                          │
│  ┌────────────┐    ┌─────────────┐    ┌───────────┐    ┌─────────────┐   │
│  │  Overview  │    │Observability│    │  FinOps   │    │Agents/Audit │   │
│  │ (Cmd Ctr)  │    │    (Pro)    │    │   (Pro)   │    │ (All Plans) │   │
│  └────────────┘    └─────────────┘    └───────────┘    └─────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

**Data flow:**

1. Your agents call Drako SDK for trust evaluation, audit logging, and policy checks
2. The backend processes each request, tracks metrics in Postgres/Redis, and emits Prometheus counters
3. Grafana Alloy scrapes `/metrics` every 30s and pushes to Grafana Cloud
4. The dashboard fetches aggregated data via REST API and receives live updates via WebSocket
5. All data is tenant-isolated via PostgreSQL Row-Level Security (RLS)

---

## Dashboard Overview

**Route:** `/dashboard`

The command center provides a real-time snapshot of your governance posture.

### Metric Cards (top row)

| Metric | Source | Description |
|--------|--------|-------------|
| **Audit Entries** | `GET /dashboard/stats` | Total audit log entries in the current period |
| **Agents Verified** | `GET /dashboard/stats` | Number of agents with completed trust evaluation |
| **Policy Blocks** | `GET /dashboard/stats` | Actions blocked by governance policies |
| **Avg Trust Score** | `GET /dashboard/agents` | Fleet-wide average trust score (0.0 - 1.0) |

Each card includes a **sparkline** showing the 7-day trend.

### Quota Usage Bar

A horizontal progress bar showing your current plan usage:
- **Green** — Under 70% of monthly quota
- **Yellow** — 70-90% of monthly quota
- **Red** — Over 90% of monthly quota

### Governance Score Trend

A time-series chart showing your governance score progression over the last 30 days, sourced from `GET /dashboard/score-progression`.

### Tool Health Grid

A visual grid of your tools' circuit breaker states:
- **Green (CLOSED)** — Tool is healthy and operating normally
- **Yellow (HALF_OPEN)** — Tool is recovering, limited traffic allowed
- **Red (OPEN)** — Tool is circuit-broken, requests are being rejected

Data from `GET /dashboard/tools/circuit-breaker/overview`.

### Activity Feed

Real-time stream of the latest audit log entries with auto-refresh every 30 seconds. Connected to the WebSocket for instant updates.

---

## Observability Page

**Route:** `/observability`  
**Plan:** Pro and above

The observability page is organized in four tabs: Overview, Metrics, Violations, and Alerts.

### Health Overview

**Tab:** Overview

Unified health assessment combining multiple signals:

| Component | What it measures |
|-----------|-----------------|
| **Health Grade** | A-F composite grade factoring latency, error rate, and governance overhead |
| **P50 Latency** | Median request latency across all endpoints |
| **P95 Latency** | 95th percentile latency (tail performance) |
| **Active Alerts** | Number of currently firing alert rules |
| **Drift Status** | Whether behavioral drift has been detected in the fleet |

Data sources:
- `GET /observability/insights/health`
- `GET /observability/alerts`
- `GET /observability/insights/drift`

### Metrics

**Tab:** Metrics

Deep performance analytics:

**Latency Time Series** — Line chart with three lines (P50, P95, P99) showing how your latency evolves over time. Spikes are immediately visible.

**Top 5 Bottlenecks** — Horizontal bar chart showing your slowest tools. If a tool consistently appears here, it's a candidate for optimization or caching.

**Cost by Model** — Donut chart showing how your LLM spend distributes across models (GPT-4, Claude, etc.). Helps identify if you're over-relying on expensive models.

**Loop Detection** — Table listing detected execution loops where agents get stuck in repeated tool calls. Each entry shows the agent, tool chain, and iteration count.

Data sources:
- `GET /observability/metrics`
- `GET /observability/metrics/bottlenecks`
- `GET /observability/metrics/loops`

### Violations

**Tab:** Violations

Policy violation analytics:

**Violation Heatmap** — A 7x24 grid (days x hours) where each cell's intensity represents the number of violations. Quickly spot patterns like "violations spike at 2 AM when batch jobs run."

**Top Violations** — Ranked list of the most frequent violation types.

**Drift Detection** — Cards showing behavioral drift metrics. Drift occurs when an agent's behavior deviates significantly from its historical pattern.

Data sources:
- `GET /observability/insights/violations`
- `GET /observability/insights/drift`

### Alerts

**Tab:** Alerts

Configurable alert rules with 9 available business metrics:

| Metric | Example threshold |
|--------|-------------------|
| `fleet_health` | < 0.7 |
| `drift_rate` | > 0.3 |
| `violations_24h` | > 100 |
| `cost_today_usd` | > 50 |
| `avg_latency_ms` | > 2000 |
| `error_rate` | > 0.05 |
| `quota_usage_pct` | > 0.9 |
| `active_agents` | < 1 |
| `governance_overhead_pct` | > 0.15 |

Each rule shows its current status, last evaluation, and firing history. Rules can be test-fired to verify they work before going live.

Alert channels: log, Slack, email, PagerDuty.

Data sources:
- `GET /observability/alerts`
- `GET /observability/alerts/events`
- `POST /observability/alerts/test`

---

## FinOps

**Route:** `/finops`  
**Plan:** Pro and above

AI cost management and optimization:

### Summary Cards

| Metric | Description |
|--------|-------------|
| **Total Spend** | Monthly LLM cost across all models and agents |
| **Top Model** | Most expensive model in the current period |
| **Cache Hit Rate** | Percentage of requests served from cache (saves money) |

### Cost by Model (Donut Chart)

Visual breakdown of spend per LLM model. Common models: GPT-4o, Claude Sonnet, GPT-4o-mini, etc.

### Cost by Agent (Bar Chart)

Per-agent cost breakdown. Identifies your most expensive agents so you can optimize their tool usage or switch to cheaper models.

### Budget Tracking (Time Series)

Monthly budget burn-down chart showing:
- **Actual spend** (solid line) — what you've spent so far
- **Budget limit** (dashed line) — your monthly budget cap
- **Projected** (dotted line) — where you'll end up at current burn rate

Data sources:
- `GET /finops/summary`
- `GET /finops/model-breakdown`
- `GET /finops/agent-breakdown`
- `GET /finops/budget`

---

## Real-Time Updates

The dashboard connects to a WebSocket at `wss://api.getdrako.com/ws` for live updates:

| Topic | Events |
|-------|--------|
| `audit` | New audit log entries as they happen |
| `agents` | Agent status changes, trust score updates |
| `tasks` | Task completion events |

The connection indicator in the dashboard header shows:
- **Green dot (pulsing)** — Connected, receiving live data
- **Yellow dot** — Reconnecting...
- **No dot** — Disconnected (data still refreshes every 30s via polling)

Reconnection is automatic with exponential backoff (up to 5 retries).

---

## Metrics Reference

### Prometheus Metrics (Infrastructure)

Exposed at `GET /metrics` (scraped by Grafana Alloy):

| Metric | Type | Description |
|--------|------|-------------|
| `http_request_duration_seconds` | Histogram | Request latency by handler, method, status |
| `http_request_size_bytes` | Histogram | Request body size |
| `http_response_size_bytes` | Histogram | Response body size |
| `http_requests_total` | Counter | Total request count |
| `drako_inprogress_requests` | Gauge | Currently in-flight requests |
| `mcp_requests_total` | Counter | MCP protocol requests |
| `mcp_tool_calls_total` | Counter | Tool invocations |
| `mcp_tool_duration_seconds` | Histogram | Tool execution latency |
| `mcp_audit_entries_total` | Counter | Audit entries created |
| `mcp_active_connections` | Gauge | Active MCP connections |

### Business Metrics (Dashboard API)

Available via REST API and used in the dashboard charts:

| Metric | Endpoint | Update frequency |
|--------|----------|-----------------|
| Audit count | `GET /dashboard/stats` | Real-time |
| Agent trust scores | `GET /dashboard/agents` | Real-time |
| Policy blocks | `GET /dashboard/stats` | Real-time |
| Quota usage | `GET /dashboard/stats` | Real-time |
| Governance score | `GET /dashboard/score-progression` | Daily |
| Circuit breaker states | `GET /dashboard/tools/circuit-breaker/overview` | 30s |
| Latency P50/P95/P99 | `GET /observability/metrics` | 30s |
| Cost per model | `GET /finops/model-breakdown` | Hourly |
| Violation counts | `GET /observability/insights/violations` | 30s |
| Drift score | `GET /observability/insights/drift` | 5min |

---

## Plan Availability

| Feature | Free | Starter | Pro | Enterprise |
|---------|------|---------|-----|------------|
| Dashboard Overview | Yes | Yes | Yes | Yes |
| Audit Trail | 7 days | 30 days | 90 days | Custom |
| Agent Trust Scores | Yes | Yes | Yes | Yes |
| Quota Usage | Yes | Yes | Yes | Yes |
| Governance Score Trend | — | Yes | Yes | Yes |
| Tool Health Grid | — | — | Yes | Yes |
| Observability (full) | — | — | Yes | Yes |
| FinOps | — | — | Yes | Yes |
| Alert Rules | — | — | Yes | Yes |
| Violation Heatmap | — | — | Yes | Yes |
| Drift Detection | — | — | Yes | Yes |
| OTEL Export | — | — | Yes | Yes |
| Custom Metrics | — | — | — | Yes |

Features not available on your plan show a **plan gate** with an upgrade prompt.
