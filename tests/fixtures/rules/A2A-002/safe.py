# ok: A2A-002
# Agent validates input from other agents via injection detection
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")

# Inter-agent message goes through A2A gateway with worm detection
result = researcher.run(task="Research topic")

# Validate agent input before passing
sanitize_agent_message = True
injection_detect = True
validate_agent_input(result)

writer.delegate(task=result, to=writer)
