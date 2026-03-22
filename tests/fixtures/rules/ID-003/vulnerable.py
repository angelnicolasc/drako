# ruleid: ID-003
# Shared credentials across multiple agents (same api_key variable in multiple files)
from crewai import Agent

# File: agent_a.py
api_key = "from-vault"
agent_a = Agent(name="agent_a", role="Researcher", api_key=api_key)

# File: agent_b.py (same credential variable reused)
api_key = "from-vault"
agent_b = Agent(name="agent_b", role="Writer", api_key=api_key)
