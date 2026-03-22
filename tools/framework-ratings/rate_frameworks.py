#!/usr/bin/env python3
"""Scan popular AI agent framework examples and produce governance ratings.

Usage:
    python rate_frameworks.py --output output/
    python rate_frameworks.py --frameworks crewai langgraph --skip-clone
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import click

from default_analysis import analyze_defaults
from framework_configs import FrameworkConfig, get_framework_configs
from report_generator import build_report, write_html_report, write_json_report


def _clone_repo(repo_url: str, dest: Path) -> bool:
    """Shallow-clone *repo_url* into *dest*.  Returns True on success."""
    if dest.exists():
        click.echo(f"  Repo already present at {dest}, reusing.")
        return True

    click.echo(f"  Cloning {repo_url} ...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", repo_url, str(dest)],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return True
    except subprocess.CalledProcessError as exc:
        click.echo(f"  [WARN] Clone failed: {exc.stderr.strip()}", err=True)
        return False
    except FileNotFoundError:
        click.echo("  [ERROR] git is not installed or not on PATH.", err=True)
        return False
    except subprocess.TimeoutExpired:
        click.echo("  [WARN] Clone timed out after 300 s.", err=True)
        return False


def _run_drako_scan(target: Path) -> dict[str, Any] | None:
    """Run ``drako scan <target> --format json`` and return parsed results."""
    if not target.exists():
        click.echo(f"    Path not found: {target}")
        return None

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "drako.cli.main", "scan", str(target), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        # Fallback: try the CLI entrypoint directly.
        try:
            proc = subprocess.run(
                ["drako", "scan", str(target), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            click.echo("    [ERROR] drako CLI not available.", err=True)
            return None
    except subprocess.TimeoutExpired:
        click.echo(f"    [WARN] Scan timed out for {target}", err=True)
        return None

    output = proc.stdout.strip()
    if not output:
        click.echo(f"    [WARN] No output from scan of {target}", err=True)
        return None

    try:
        return json.loads(output)  # type: ignore[no-any-return]
    except json.JSONDecodeError:
        click.echo(f"    [WARN] Could not parse scan output for {target}", err=True)
        return None


def _extract_score_and_findings(scan_result: dict[str, Any]) -> tuple[float, list[dict]]:
    """Extract the numeric score and findings list from a Drako JSON report."""
    score = scan_result.get("score")
    if score is None:
        score = scan_result.get("governance_score")
    if score is None:
        score = 50.0

    findings: list[dict] = []
    for item in scan_result.get("findings", scan_result.get("violations", [])):
        findings.append(
            {
                "rule": item.get("rule", item.get("id", "unknown")),
                "severity": item.get("severity", "medium"),
                "message": item.get("message", item.get("description", "")),
                "file": item.get("file", item.get("location", "")),
            }
        )
    return float(score), findings


def rate_single_framework(
    config: FrameworkConfig,
    clone_dir: Path,
    skip_clone: bool,
) -> dict[str, Any]:
    """Clone, scan, and rate a single framework.  Returns a result dict."""
    click.echo(f"\n{'='*60}")
    click.echo(f"Rating: {config.display_name}")
    click.echo(f"{'='*60}")

    errors: list[str] = []
    repo_dir = clone_dir / config.name

    # 1. Clone -----------------------------------------------------------
    if not skip_clone:
        ok = _clone_repo(config.repo_url, repo_dir)
        if not ok:
            errors.append(f"Failed to clone {config.repo_url}")
    else:
        if not repo_dir.exists():
            errors.append(f"--skip-clone set but {repo_dir} does not exist")

    # 2. Scan each example path ------------------------------------------
    example_scores: list[dict[str, Any]] = []

    if repo_dir.exists():
        paths_to_scan = config.example_paths if config.example_paths else ["."]
        for rel_path in paths_to_scan:
            target = repo_dir / rel_path
            click.echo(f"  Scanning {rel_path} ...")
            result = _run_drako_scan(target)
            if result is not None:
                score, findings = _extract_score_and_findings(result)
                example_scores.append(
                    {
                        "path": rel_path,
                        "score": score,
                        "findings": findings,
                        "findings_count": len(findings),
                    }
                )
                click.echo(f"    Score: {score:.1f}  |  Findings: {len(findings)}")
            else:
                example_scores.append(
                    {
                        "path": rel_path,
                        "score": None,
                        "findings": [],
                        "findings_count": 0,
                        "error": "Scan failed or path not found",
                    }
                )
                errors.append(f"Scan failed for {rel_path}")
    else:
        errors.append("Repository not available; skipping example scans.")

    # 3. Default analysis ------------------------------------------------
    modifier, default_details = analyze_defaults(config.defaults)
    click.echo(f"  Default modifier: {modifier:+d}")

    return {
        "name": config.name,
        "display_name": config.display_name,
        "example_scores": example_scores,
        "default_modifier": modifier,
        "default_details": default_details,
        "strengths": config.strengths,
        "errors": errors,
    }


@click.command()
@click.option(
    "--output",
    "output_dir",
    type=click.Path(path_type=Path),
    default=Path(__file__).resolve().parent / "output",
    show_default=True,
    help="Directory for generated reports.",
)
@click.option(
    "--skip-clone",
    is_flag=True,
    default=False,
    help="Reuse already-cloned repositories instead of cloning fresh.",
)
@click.option(
    "--frameworks",
    multiple=True,
    help="Restrict to specific framework names (repeatable).",
)
@click.option(
    "--clone-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory for cloned repos.  Defaults to a temporary directory.",
)
def main(
    output_dir: Path,
    skip_clone: bool,
    frameworks: tuple[str, ...],
    clone_dir: Path | None,
) -> None:
    """Scan AI agent framework examples and generate governance ratings."""
    configs = get_framework_configs(list(frameworks) if frameworks else None)

    use_temp = clone_dir is None and not skip_clone
    if use_temp:
        _tmp = tempfile.mkdtemp(prefix="drako-fw-")
        clone_dir = Path(_tmp)
        click.echo(f"Using temp clone dir: {clone_dir}")
    elif clone_dir is None:
        clone_dir = Path(__file__).resolve().parent / "repos"

    clone_dir.mkdir(parents=True, exist_ok=True)

    # Rate each framework ------------------------------------------------
    results: list[dict[str, Any]] = []
    for config in configs:
        fw_result = rate_single_framework(config, clone_dir, skip_clone)
        results.append(fw_result)

    # Build and write reports --------------------------------------------
    report = build_report(results)

    json_path = write_json_report(report, output_dir)
    click.echo(f"\nJSON report: {json_path}")

    html_path = write_html_report(report, output_dir)
    click.echo(f"HTML report: {html_path}")

    # Summary table ------------------------------------------------------
    click.echo(f"\n{'='*60}")
    click.echo("GOVERNANCE RATINGS SUMMARY")
    click.echo(f"{'='*60}")
    click.echo(f"{'Framework':<25} {'Grade':>5} {'Score':>7}")
    click.echo("-" * 40)

    ranked = sorted(
        report["frameworks"].items(),
        key=lambda kv: kv[1]["score"],
        reverse=True,
    )
    for _name, data in ranked:
        click.echo(f"{data['display_name']:<25} {data['grade']:>5} {data['score']:>7.1f}")

    # Cleanup temp dir ---------------------------------------------------
    if use_temp:
        click.echo(f"\nCleaning up temp dir: {clone_dir}")
        shutil.rmtree(clone_dir, ignore_errors=True)

    click.echo("\nDone.")


if __name__ == "__main__":
    main()
