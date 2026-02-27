"""AgentMesh CLI — entry point."""

from __future__ import annotations

import click

from agentmesh import __version__


@click.group()
@click.version_option(version=__version__, prog_name="agentmesh")
def cli() -> None:
    """AgentMesh — The Trust Layer for AI Agents."""


# Register sub-commands (lazy imports keep startup fast)
def _register_commands() -> None:
    from agentmesh.cli.init_command import init
    from agentmesh.cli.scan_command import scan
    from agentmesh.cli.serve_command import serve
    from agentmesh.cli.status_command import status
    from agentmesh.cli.verify_command import verify

    cli.add_command(init)
    cli.add_command(scan)
    cli.add_command(serve)
    cli.add_command(status)
    cli.add_command(verify)


_register_commands()

if __name__ == "__main__":
    cli()
