# ok: GOV-009
# Destructive tool with human approval gate
from crewai import Agent
from crewai_tools import tool


@tool
def delete_user(user_id: str) -> str:
    if not require_approval(f"Delete user {user_id}"):
        return "Action cancelled by human_in_the_loop"
    return f"User {user_id} deleted"


def require_approval(action):
    return True


agent = Agent(name="admin", tools=[delete_user])
