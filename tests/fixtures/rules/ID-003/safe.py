# ok: ID-003
# Each agent uses unique, independently managed credentials
import os
from crewai import Agent

researcher_cred = os.environ["AGENT_A_API_KEY"]
writer_cred = os.environ["AGENT_B_API_KEY"]

agent_a = Agent(
    name="agent_a",
    role="Researcher",
    llm=researcher_cred,
)

agent_b = Agent(
    name="agent_b",
    role="Writer",
    llm=writer_cred,
)
