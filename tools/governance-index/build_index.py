# mypy: strict
"""Public Agent Governance Index — CLI entry point.

Discovers top AI agent repos on GitHub, scans each with Drako,
and produces aggregate statistics + benchmark dataset.

Usage:
    python build_index.py --token $GITHUB_TOKEN
    python build_index.py --token $GITHUB_TOKEN --limit 10 --resume
    python build_index.py --token $GITHUB_TOKEN --update-sdk
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from checkpoint import load_checkpoint, save_checkpoint
from dataset_generator import generate_dataset, save_dataset
from github_discovery import RepoInfo, discover_repos
from report_generator import generate_html_report, generate_json_report
from scan_runner import RepoScanResult, cleanup_repo, scan_repo

# SDK data directory (relative to this tool's location)
_SDK_DATA_DIR = Path(__file__).parent.parent.parent / "sdk" / "src" / "drako" / "data"


@click.command()
@click.option(
    "--token",
    envvar="GITHUB_TOKEN",
    required=True,
    help="GitHub personal access token (env: GITHUB_TOKEN)",
)
@click.option(
    "--output", "output_dir",
    type=click.Path(),
    default="output",
    help="Output directory for reports (default: output/)",
)
@click.option(
    "--limit",
    type=int,
    default=100,
    help="Maximum repos to scan (default: 100)",
)
@click.option(
    "--min-stars",
    type=int,
    default=100,
    help="Minimum star count for repo inclusion (default: 100)",
)
@click.option(
    "--resume",
    is_flag=True,
    help="Resume from checkpoint if available",
)
@click.option(
    "--skip-clone",
    is_flag=True,
    help="Skip clone for already-cloned repos in work/",
)
@click.option(
    "--update-sdk",
    is_flag=True,
    help="Copy benchmark_dataset.json to SDK data directory",
)
@click.option(
    "--keep-clones",
    is_flag=True,
    help="Keep cloned repos after scanning (default: cleanup)",
)
def main(
    token: str,
    output_dir: str,
    limit: int,
    min_stars: int,
    resume: bool,
    skip_clone: bool,
    update_sdk: bool,
    keep_clones: bool,
) -> None:
    """Build the Public Agent Governance Index."""
    out = Path(output_dir)
    work = Path("work")
    work.mkdir(parents=True, exist_ok=True)

    # --- Phase 1: Discovery ---
    click.echo("Phase 1: Discovering AI agent repos on GitHub...")
    repos = discover_repos(token=token, min_stars=min_stars, limit=limit)
    click.echo(f"  Found {len(repos)} repos (min {min_stars} stars)")

    if not repos:
        click.secho("No repos found. Check your token and try again.", fg="red")
        sys.exit(1)

    # --- Phase 2: Load checkpoint ---
    completed: dict[str, RepoScanResult] = {}
    if resume:
        checkpoint = load_checkpoint(out)
        if checkpoint is not None:
            completed, _ = checkpoint
            click.echo(f"  Resumed from checkpoint: {len(completed)} repos already scanned")

    # --- Phase 3: Scan ---
    click.echo(f"Phase 2: Scanning {len(repos)} repos...")
    pending = [r for r in repos if r.full_name not in completed]
    click.echo(f"  {len(pending)} repos to scan ({len(completed)} from checkpoint)")

    for i, repo in enumerate(pending, 1):
        click.echo(f"  [{i}/{len(pending)}] {repo.full_name} ({repo.stars}\u2605)...", nl=False)

        result = scan_repo(repo, work_dir=work)
        if result is not None:
            completed[repo.full_name] = result
            grade_colors = {"A": "green", "B": "bright_green", "C": "yellow", "D": "red", "F": "red"}
            color = grade_colors.get(result.grade, "white")
            click.echo(" ", nl=False)
            click.secho(f"{result.score}/100 [{result.grade}]", fg=color)

            if not keep_clones:
                cleanup_repo(repo, work)
        else:
            click.secho(" SKIP", fg="yellow")

        # Save checkpoint after each repo
        remaining_names = [r.full_name for r in pending[i:]]
        save_checkpoint(completed, remaining_names, out)

    all_results = list(completed.values())
    click.echo(f"\n  Successfully scanned {len(all_results)}/{len(repos)} repos")

    if not all_results:
        click.secho("No repos could be scanned.", fg="red")
        sys.exit(1)

    # --- Phase 4: Generate outputs ---
    click.echo("Phase 3: Generating reports...")

    # Benchmark dataset
    dataset = generate_dataset(all_results)
    sdk_dir = _SDK_DATA_DIR if update_sdk else None
    dataset_paths = save_dataset(dataset, out, sdk_data_dir=sdk_dir)
    for p in dataset_paths:
        click.echo(f"  Dataset: {p}")

    # JSON + HTML reports
    json_path = generate_json_report(all_results, out)
    click.echo(f"  JSON report: {json_path}")

    html_path = generate_html_report(all_results, out)
    click.echo(f"  HTML report: {html_path}")

    # Summary
    avg = round(sum(r.score for r in all_results) / len(all_results))
    click.echo()
    click.echo(f"  {len(all_results)} projects scanned — average score: {avg}/100")

    if update_sdk:
        click.secho(f"  SDK benchmark dataset updated at {_SDK_DATA_DIR}/benchmark_dataset.json", fg="green")


if __name__ == "__main__":
    main()
