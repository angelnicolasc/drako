# ruleid: SEC-011
# High-impact tools without intent verification
from crewai import Agent
from crewai_tools import tool


@tool
def send_money(account: str, amount: float) -> str:
    return f"Transferred {amount} to {account}"


@tool
def remove_data(table: str) -> str:
    return f"Deleted all from {table}"


agent = Agent(name="finbot", tools=[send_money, remove_data])
