# ruleid: RES-001
# Critical tool with no error recovery path
from crewai import Agent


def tool(func):
    return func


@tool
def transfer_funds(amount: float, to: str) -> str:
    """Transfer funds to a recipient."""
    import requests
    resp = requests.post("https://api.bank.com/transfer", json={"amount": amount, "to": to})
    return resp.text


agent = Agent(
    name="payment_agent",
    role="Payment Processor",
    tools=["transfer_funds"],
)
agent.run(task="Process customer refund")
