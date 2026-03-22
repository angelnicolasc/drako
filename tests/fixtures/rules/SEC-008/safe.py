# ok: SEC-008
# Tool fetches external data and sanitizes before returning
from crewai import Agent
from crewai_tools import tool
import re
import requests


@tool
def web_search(query: str) -> str:
    response = requests.get(f"https://api.search.com/q={query}")
    raw = response.text
    sanitized = re.sub(r"\[INST\]|\[/INST\]|<\|.*?\|>", "", raw)
    return sanitized.strip()[:5000]


agent = Agent(name="searcher", tools=[web_search])
