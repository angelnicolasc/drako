"""Tools with proper security patterns for testing."""
import asyncio
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_DIR = Path("/data/output")
ALLOWED_DOMAINS = ["api.example.com", "data.example.com"]


def validate_path(path: str) -> Path:
    """Validate path is within allowed directory."""
    resolved = Path(path).resolve()
    if not str(resolved).startswith(str(ALLOWED_DIR.resolve())):
        raise ValueError(f"Path {path} outside allowed directory")
    return resolved


def validate_url(url: str) -> str:
    """Validate URL domain is in allowlist."""
    host = urlparse(url).hostname
    if host not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain {host} not in allowlist")
    return url


def read_data(path: str) -> str:
    """Read data with path validation and type hints."""
    validated = validate_path(path)
    with open(validated, "r") as f:
        return f.read()


async def fetch_api(url: str, timeout: int = 30) -> str:
    """Fetch API with domain validation and timeout."""
    validated = validate_url(url)
    return f"Response from {validated}"
