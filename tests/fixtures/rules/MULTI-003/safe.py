# ok: MULTI-003
# Agents use separate tools OR contention protection is enabled
from crewai import Agent

agent_a = Agent(name="agent_a", role="Writer", tools=["database_write"])
agent_b = Agent(name="agent_b", role="Reader", tools=["database_read"])

# topology conflict_detection enabled for resource_contention
# topology:
#   enabled: true
#   conflict_detection:
#     resource_contention: true
