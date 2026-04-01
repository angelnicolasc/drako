"""Allow python -m drako.mcp to start the server."""
import sys

from drako.cli.main import cli

cli(["serve"] + sys.argv[1:])
