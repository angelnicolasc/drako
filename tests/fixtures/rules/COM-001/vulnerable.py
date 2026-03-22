# ruleid: COM-001
# No automatic logging configured (EU AI Act Art. 12)
from crewai import Agent

agent = Agent(
    name="processor",
    system_prompt="You process data and generate reports.",
)
