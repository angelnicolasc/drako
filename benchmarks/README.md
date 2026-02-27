# AgentMesh SDK Benchmarks

Professional benchmark suite for measuring the latency and overhead of the AgentMesh SDK components.

## Methodology

*   **Precision:** Nanosecond precision using `time.perf_counter_ns()`.
*   **Warmups:** Each test has a configured set of warmup iterations (10-1,000 based on test duration) to ensure the JIT compiler and memory states are stable.
*   **Memory:** `tracemalloc` is used to trace peak memory footprint.
*   **Hardware and Environment:** Standard execution in Local OS.

## Benchmarks Included

*   `bench_policy_engine.py`: Evaluates deterministic rules via `agentmesh.cli.policies`. We target `<10ms` for full AST policy inference scans to claim that governance is `<1%` of an average LLM call overhead (~800ms).
*   `bench_discovery.py`: Latency of offline Agent/Tool/Model and framework Discovery (AST parser).
*   `bench_dlp.py`: Local PII/PCI scanning through Microsoft Presidio.

## Running

It is recommended to run benchmarks in a virtual environment with `rich` installed for best formatting.

```bash
python sdk/benchmarks/run_all.py
```

### Competitor Comparison

| Agent Governance Wrapper | Language | Single Policy Latency |
| :--- | :--- | :--- |
| **Bifrost** | Go | ~0.011 ms (11µs) |
| **AgentBouncr** | TypeScript | <5 ms |
| **LiteLLM Guardrails** | Python | ~0.44 ms (440µs) |
| **AgentMesh SDK** | Python | **<10 ms (Target)** |

If Policy rule evaluation goes consistently beyond 10ms in critical workloads for AST extraction, document potential optimizations or consider a rust-based module (PyO3).
