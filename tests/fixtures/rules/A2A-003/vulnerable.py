# ruleid: A2A-003
# Agents share state without channel isolation
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")

# Shared memory / global state without isolation
shared_memory = {}
shared_context = {"messages": [], "data": {}}

researcher.context = shared_context
writer.context = shared_context  # same context object — no isolation
