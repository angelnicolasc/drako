# ok: SEC-004
# Tool with network access and domain allowlist
from crewai import Agent
from crewai_tools import tool
from urllib.parse import urlparse
import requests

ALLOWED_DOMAINS = ["api.example.com", "data.example.com"]


@tool
def fetch_data(url: str) -> str:
    host = urlparse(url).hostname
    if host not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain {host} not in allowlist")
    response = requests.get(url)
    return response.text


agent = Agent(name="fetcher", tools=[fetch_data])
