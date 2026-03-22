# ok: A2A-003
# Agents use isolated communication channels / scoped context
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")

# Channel isolation: each agent has scoped_context
researcher_channel = {"namespace": "researcher", "scoped_context": {}}
writer_channel = {"namespace": "writer", "scoped_context": {}}

# message_channel configured per agent pair
channel_isolation = True
private_channel = {"from": "researcher", "to": "writer"}
