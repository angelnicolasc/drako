# ruleid: GOV-010
# Missing human-in-the-loop routing
from crewai import Agent

agent = Agent(
    name="processor",
    system_prompt="You process data and generate reports.",
)
