# ok: GOV-007
# Tool makes external calls with proper error handling
from crewai import Agent
from crewai_tools import tool
import requests


@tool
def fetch_api(endpoint: str) -> str:
    try:
        response = requests.get(endpoint, timeout=10)
        return response.json()
    except (requests.ConnectionError, requests.Timeout) as e:
        return f"API temporarily unavailable: {e}"


agent = Agent(name="api_caller", tools=[fetch_api])
