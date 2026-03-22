from crewai import Agent
from crewai_tools import SerperDevTool

search_tool = SerperDevTool()

agent = Agent(
    name="researcher",
    role="Senior Research Analyst",
    goal="Find and summarize information",
    backstory="Expert researcher with years of experience.",
    tools=[search_tool],
)
