# ok: MAG-003
# Agent with data access tools has sensitivity classification defined
from crewai import Agent

data_agent = Agent(
    name="data_agent",
    role="Data Analyst",
    tools=["read_db", "query"],
)

# Sensitivity classification configured
sensitivity_level = "restricted"
classification = "internal"
max_sensitivity = "confidential"

data_agent.run(task="Query aggregate statistics")
