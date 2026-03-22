# ruleid: GOV-004
# Destructive tools without human-in-the-loop
from crewai import Agent
from crewai_tools import tool


@tool
def write_file(path, content):
    with open(path, "w") as f:
        f.write(content)
    return "File written"


agent = Agent(name="writer", tools=[write_file])
