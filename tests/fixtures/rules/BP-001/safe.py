# ok: BP-001
# Using the current version of crewai
from crewai import Agent

# Project uses up-to-date crewai (version from setup.py overrides requirements.txt)
agent = Agent(name="researcher", role="researcher")
