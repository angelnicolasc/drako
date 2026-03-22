# ok: MULTI-002
# Unidirectional agent delegation — no circular dependencies
from crewai import Agent

a = Agent(name="alpha", role="Research Agent")
b = Agent(name="beta", role="Writing Agent")

# One-way delegation: alpha -> beta (no cycle)
a.delegate(task="write_draft", to=b)
