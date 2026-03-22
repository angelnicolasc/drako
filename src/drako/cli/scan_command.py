"""`drako scan` — Scan a project for governance/compliance gaps.

Offline-first: all analysis runs locally using AST. No network calls
unless --upload is passed. No signup or API key required for basic use.
"""

from __future__ import annotations

import sys

import click


@click.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option(
    "--format", "output_format",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    help="Output format (default: terminal with Rich)",
)
@click.option(
    "--upload",
    is_flag=True,
    help="Upload results to Drako for shareable URL and badge",
)
@click.option(
    "--api-key",
    envvar="DRAKO_API_KEY",
    default=None,
    help="API key for authenticated upload (env: DRAKO_API_KEY)",
)
@click.option(
    "--endpoint",
    default="https://api.getdrako.com",
    envvar="DRAKO_ENDPOINT",
    help="Backend endpoint for --upload",
)
@click.option(
    "--framework",
    default=None,
    help="Comma-separated frameworks to detect (e.g. crewai,langgraph)",
)
@click.option(
    "--share",
    is_flag=True,
    help="Show shareable score card and pre-redacted social posts",
)
@click.option(
    "--details",
    is_flag=True,
    help="Show impact analysis and attack scenarios for each finding",
)
@click.option(
    "--baseline",
    "save_baseline",
    is_flag=True,
    help="Save current findings as the baseline for future scans",
)
@click.option(
    "--show-all",
    is_flag=True,
    help="Show all findings, ignoring the baseline",
)
@click.option(
    "--benchmark",
    is_flag=True,
    help="Compare your score against anonymized benchmark data",
)
@click.option(
    "--determinism",
    is_flag=True,
    help="Show only determinism findings (DET-* rules)",
)
@click.option(
    "--threshold-det",
    type=int,
    default=0,
    help="Minimum determinism score (exit 1 if below). For CI gating.",
)
def scan(
    directory: str,
    output_format: str,
    upload: bool,
    api_key: str | None,
    endpoint: str,
    framework: str | None,
    share: bool,
    details: bool,
    save_baseline: bool,
    show_all: bool,
    benchmark: bool,
    determinism: bool,
    threshold_det: int,
) -> None:
    """Scan your AI agent project for governance and compliance gaps.

    Analyzes the project at DIRECTORY (defaults to current directory)
    and generates a governance score, Agent BOM, and actionable findings.

    All analysis runs offline — no network calls, no signup required.
    """
    # Lazy imports keep CLI startup fast
    from drako.cli.scanner import run_scan

    # Parse framework filter
    framework_filter = None
    if framework:
        framework_filter = [f.strip() for f in framework.split(",") if f.strip()]

    # ---- Run offline scan ----
    result = run_scan(directory, framework_filter=framework_filter)

    # ---- Determinism filter ----
    if determinism:
        result.findings = [f for f in result.findings if f.category == "Determinism"]

    # ---- Baseline handling ----
    from drako.cli.baseline import Baseline

    bl = Baseline(directory)
    all_findings = result.findings  # Always used for scoring
    display_findings = all_findings
    baselined_count = 0
    resolved_count = 0

    if save_baseline:
        path = bl.save(all_findings)
        if output_format == "terminal":
            click.echo(
                click.style("  [baseline] ", fg="green")
                + f"Saved {len(all_findings)} findings as baseline to {path}"
            )
        else:
            click.echo(
                f"  [baseline] Saved {len(all_findings)} findings to {path}",
                err=True,
            )
    elif bl.exists() and not show_all:
        new_findings, baselined_findings, resolved_fps = bl.filter_findings(all_findings)
        display_findings = new_findings
        baselined_count = len(baselined_findings)
        resolved_count = len(resolved_fps)

    # ---- Cache scan results for `drako init` ----
    from drako.cli.scan_cache import save_scan_cache, ensure_gitignore_cache
    try:
        save_scan_cache(result, directory)
        ensure_gitignore_cache(directory)
        if output_format == "terminal":
            click.echo(click.style("  [cache]  ", fg="green") + "Scan results saved to .drako/.last_scan.json")
        else:
            click.echo("  [cache]  Scan results saved to .drako/.last_scan.json", err=True)
    except OSError:
        pass  # Non-critical — don't fail the scan if cache write fails

    # ---- Benchmark (lazy, only when flag is set) ----
    benchmark_result = None
    if benchmark:
        from drako.benchmark import compute_benchmark, load_dataset
        dataset = load_dataset()
        fw_name = result.bom.frameworks[0].name if result.bom.frameworks else None
        benchmark_result = compute_benchmark(result.score, fw_name, dataset)

    # ---- Output based on format ----
    if output_format == "json":
        from drako.cli.formats.json_fmt import format_json
        click.echo(format_json(result, benchmark=benchmark_result))

    elif output_format == "sarif":
        from drako.cli.formats.sarif import format_sarif

        # Pass baseline fingerprints for baselineState marking
        baseline_fps: set[str] | None = None
        if bl.exists() and not show_all:
            data = bl.load()
            if data:
                baseline_fps = set(data["fingerprints"].keys())

        click.echo(format_sarif(result, baseline_fingerprints=baseline_fps))

    else:
        # Terminal output with Rich
        from drako.cli.report import render_report
        render_report(
            bom=result.bom,
            findings=display_findings,
            score=result.score,
            grade=result.grade,
            metadata=result.metadata,
            scan_duration_ms=result.scan_duration_ms,
            details=details,
            baselined_count=baselined_count,
            resolved_count=resolved_count,
            determinism_score=result.determinism_score,
            determinism_grade=result.determinism_grade,
            matched_advisories=result.matched_advisories,
            reachability=result.reachability,
        )
        if benchmark_result:
            from drako.cli.report import render_benchmark_panel
            render_benchmark_panel(benchmark_result, result.score, result.grade)

    # ---- Upload if requested (before share, so URL is available) ----
    scan_url: str | None = None
    if upload:
        from drako.cli.upload import upload_results
        import httpx

        click.echo()
        if api_key:
            click.echo(click.style("  [upload] ", fg="green") + "Uploading results (authenticated)...")
        else:
            click.echo(click.style("  [upload] ", fg="green") + "Uploading results (anonymous, expires in 7 days)...")

        try:
            resp = upload_results(result, api_key=api_key, endpoint=endpoint)
            scan_id = resp.get("scan_id", "?")
            scan_url = resp.get("url", "")
            click.echo(click.style("  [upload] ", fg="green") + f"Scan ID: {scan_id}")
            if scan_url:
                click.echo(
                    click.style("  [upload] ", fg="green")
                    + "Report: "
                    + click.style(scan_url, fg="cyan", underline=True)
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                click.secho("  [error]  Rate limit exceeded. Try again later or use an API key.", fg="red")
            elif e.response.status_code == 401:
                click.secho("  [error]  Invalid API key.", fg="red")
            else:
                click.secho(f"  [error]  Upload failed: HTTP {e.response.status_code}", fg="red")
        except httpx.ConnectError:
            click.secho("  [error]  Could not connect to Drako backend.", fg="red")
            click.echo("           Try: --endpoint http://localhost:8000")
        except httpx.ReadTimeout:
            click.secho("  [error]  Upload timed out.", fg="red")

    # ---- Share if requested ----
    if share:
        from drako.cli.share import run_share_flow
        run_share_flow(result, scan_url=scan_url, directory=directory)

    # ---- Telemetry (fire-and-forget, never blocks) ----
    try:
        from drako.telemetry import send_event, maybe_show_telemetry_notice

        maybe_show_telemetry_notice(directory)

        # Count findings by severity
        finding_counts = {}
        for f in result.findings:
            finding_counts[f.severity] = finding_counts.get(f.severity, 0) + 1

        send_event("scan_completed", {
            "score": result.score,
            "grade": result.grade,
            "determinism_score": result.determinism_score,
            "framework": result.bom.frameworks[0].name if result.bom.frameworks else None,
            "finding_counts": finding_counts,
            "output_format": output_format,
            "has_baseline": bl.exists(),
            "agent_count": len(result.bom.agents),
            "tool_count": len(result.bom.tools),
        })
    except Exception:
        pass  # Telemetry must never affect scan

    # ---- Exit code based on findings ----
    # Exit code is based on display_findings (new only), not all findings.
    # Score always reflects ALL findings (baselined + new).
    critical_count = sum(1 for f in display_findings if f.severity == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)

    # ---- Determinism threshold gate ----
    if threshold_det > 0 and result.determinism_score < threshold_det:
        click.secho(
            f"  [gate]  Determinism score {result.determinism_score} "
            f"below threshold {threshold_det}",
            fg="red",
        )
        sys.exit(1)
