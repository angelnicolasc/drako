from crewai import Agent
from crewai_tools import (
    CodeInterpreterTool,
    FileReadTool,
    DirectoryReadTool,
    SerperDevTool,
    WebsiteSearchTool,
    ScrapeWebsiteTool,
)

search = SerperDevTool()
websearch = WebsiteSearchTool()
scraper = ScrapeWebsiteTool()
reader = FileReadTool()
dirreader = DirectoryReadTool()
interpreter = CodeInterpreterTool()

agent = Agent(
    name="multi-tool-agent",
    role="General Purpose Assistant",
    goal="Handle various tasks using multiple tools",
    backstory="A versatile agent with many capabilities.",
    tools=[search, websearch, scraper, reader, dirreader, interpreter],
)
