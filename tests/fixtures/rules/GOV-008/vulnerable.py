# ruleid: GOV-008
# Critical tool with no fallback or retry logic
from crewai import Agent
from crewai_tools import tool


@tool
def send_email(to: str, body: str) -> str:
    return f"Email sent to {to}"


agent = Agent(name="mailer", tools=[send_email])
