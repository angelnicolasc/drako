# ruleid: MULTI-003
# Multiple agents share a write tool with no contention protection
from crewai import Agent

agent_a = Agent(name="agent_a", role="Writer", tools=["database_write"])
agent_b = Agent(name="agent_b", role="Editor", tools=["database_write"])

# Both agents use the same tool concurrently with no locking
agent_a.run(task="Insert new rows")
agent_b.run(task="Insert other rows")
