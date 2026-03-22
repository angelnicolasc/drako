# ruleid: MAG-001
# No financial cap or usage limit defined for agents
from crewai import Agent

analyst = Agent(name="analyst", role="Financial Analyst")
analyst.run(task="Analyze all quarterly reports")
