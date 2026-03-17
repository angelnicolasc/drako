"""Tools with security issues for testing."""
from crewai_tools import tool
import requests


# ruleid: SEC-003
@tool
def read_file(path):
    """Read a file from disk — no path validation."""
    with open(path, "r") as f:
        return f.read()


# ruleid: SEC-003
@tool
def write_file(path, content):
    """Write to a file — no path validation."""
    with open(path, "w") as f:
        f.write(content)


# ruleid: SEC-004
@tool
def search_web(query):
    """Search the web — no domain allowlist."""
    resp = requests.get(f"https://api.search.com/q={query}")
    return resp.text


# ruleid: SEC-004
@tool
def fetch_url(url):
    """Fetch any URL — no domain restriction."""
    resp = requests.get(url)
    return resp.text
