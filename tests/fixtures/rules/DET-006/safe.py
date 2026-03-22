from crewai import Agent
from crewai_tools import SerperDevTool, WebsiteSearchTool, ScrapeWebsiteTool

agent = Agent(
    name="web-researcher",
    role="Web Research Specialist",
    goal="Search and scrape web content",
    backstory="A focused agent for web research tasks.",
    tools=[
        SerperDevTool(),
        WebsiteSearchTool(),
        ScrapeWebsiteTool(),
    ],
)
