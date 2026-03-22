# ruleid: COM-002
# No human oversight mechanism (EU AI Act Art. 14)
from crewai import Agent

agent = Agent(
    name="autonomous_worker",
    system_prompt="You autonomously process all incoming requests.",
)
