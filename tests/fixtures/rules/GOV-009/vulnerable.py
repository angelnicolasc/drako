# ruleid: GOV-009
# Destructive tool without human approval gate
from crewai import Agent
from crewai_tools import tool


@tool
def delete_user(user_id: str) -> str:
    return f"User {user_id} deleted"


agent = Agent(name="admin", tools=[delete_user])
