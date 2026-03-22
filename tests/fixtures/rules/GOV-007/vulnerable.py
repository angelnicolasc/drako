# ruleid: GOV-007
# Tool makes external calls without error handling
from crewai import Agent
from crewai_tools import tool
import requests


@tool
def fetch_api(endpoint: str) -> str:
    response = requests.get(endpoint)
    return response.json()


agent = Agent(name="api_caller", tools=[fetch_api])
