# ok: MULTI-004
# Chaos testing / fault injection is configured
from crewai import Agent, Task, Crew

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")

crew = Crew(agents=[researcher, writer])

# Chaos experiment configured for resilience testing
chaos_experiment = {
    "name": "db-tool-failure",
    "target_tool": "database_query",
    "fault_type": "tool_deny",
    "duration_seconds": 60,
}
