# Framework Security Monitor

Monitors major AI framework repositories (CrewAI, LangChain, AutoGen, LlamaIndex, Pydantic AI, Semantic Kernel) for security-relevant commits and issues.

## How it works

1. Fetches recent commits and issues from GitHub
2. Scores each against security keywords (injection, CVE, bypass, etc.)
3. Applies path-based boosting for changes in security-critical code
4. Generates JSON alerts for human review

**No automated advisory creation** — all alerts require human triage.

## Usage

```bash
# Set GitHub token for higher rate limits
export GITHUB_TOKEN=ghp_...

# Full monitoring run
python monitor.py

# Dry run (no API calls)
python monitor.py --dry-run

# Monitor a single framework
python monitor.py --framework crewai

# Custom lookback period
python monitor.py --since 3  # last 3 days
```

## Configuration

Edit `config.yaml` to:
- Add/remove frameworks
- Adjust keyword weights
- Change monitored file paths
- Set relevance thresholds

## Output

Alerts are saved to `alerts/alerts_YYYYMMDD_HHMMSS.json`:

```json
{
  "framework": "crewai",
  "type": "commit",
  "url": "https://github.com/...",
  "title": "fix: sanitize tool output",
  "keywords_matched": ["sanitize", "fix"],
  "relevance_score": 0.85,
  "detected_at": "2026-03-20T...",
  "potential_advisory": true
}
```

## CI Integration

The monitor runs automatically every 6 hours via GitHub Actions (`.github/workflows/framework-monitor.yml`).
