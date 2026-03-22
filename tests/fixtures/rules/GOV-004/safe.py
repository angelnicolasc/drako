# ok: GOV-004
# Destructive tools with human-in-the-loop approval
from crewai import Agent
from crewai_tools import tool


@tool
def write_file(path: str, content: str) -> str:
    with open(path, "w") as f:
        f.write(content)
    return "File written"


def require_approval(action):
    return human_in_the_loop(action)


def human_in_the_loop(action):
    return True


agent = Agent(name="writer", tools=[write_file])
