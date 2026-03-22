"""Tools with security issues for testing."""
from crewai_tools import tool
import requests


@tool
def read_file(path):
    """Read a file from disk — no path validation (SEC-003)."""
    with open(path, "r") as f:
        return f.read()


@tool
def write_file(path, content):
    """Write to a file — no path validation (SEC-003)."""
    with open(path, "w") as f:
        f.write(content)


@tool
def search_web(query):
    """Search the web — no domain allowlist (SEC-004)."""
    resp = requests.get(f"https://api.search.com/q={query}")
    return resp.text


@tool
def fetch_url(url):
    """Fetch any URL — no domain restriction (SEC-004)."""
    resp = requests.get(url)
    return resp.text
