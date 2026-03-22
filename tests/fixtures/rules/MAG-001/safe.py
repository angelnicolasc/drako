# ok: MAG-001
# Spend cap / token budget is defined via magnitude_limits
from crewai import Agent

analyst = Agent(name="analyst", role="Financial Analyst")

magnitude_limits = {
    "max_budget": 10.00,
    "max_tokens": 100000,
}
analyst.run(task="Analyze all quarterly reports", limits=magnitude_limits)
