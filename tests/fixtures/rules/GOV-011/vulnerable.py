# ruleid: GOV-011
# Critical tool without replay protection / idempotency
from crewai import Agent
from crewai_tools import tool


@tool
def execute_payment(amount: float, recipient: str) -> str:
    return f"Paid {amount} to {recipient}"


agent = Agent(name="paybot", tools=[execute_payment])
