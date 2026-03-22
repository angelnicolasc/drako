# ruleid: MULTI-002
# Circular agent dependency: agent_a delegates to agent_b, agent_b delegates to agent_a
from crewai import Agent

agent_a = Agent(name="agent_a", role="Analyst")
agent_b = Agent(name="agent_b", role="Reviewer")

# agent_a calls agent_b
agent_a.delegate(task="review", to=agent_b)

# agent_b calls agent_a — creates a circular dependency
agent_b.delegate(task="analyze", to=agent_a)
