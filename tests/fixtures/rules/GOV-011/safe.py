# ok: GOV-011
# Critical tool with idempotency / replay protection
from crewai import Agent
from crewai_tools import tool

_processed = set()


@tool
def execute_payment(amount: float, recipient: str, idempotency_key: str) -> str:
    if idempotency_key in _processed:
        return "Already processed"
    _processed.add(idempotency_key)
    return f"Paid {amount} to {recipient}"


agent = Agent(name="paybot", tools=[execute_payment])
