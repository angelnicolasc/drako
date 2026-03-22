# ruleid: BP-005
# Agent with more than 10 tools registered
from crewai import Agent

researcher = Agent(
    name="overloaded_agent",
    tools=[
        "search_web", "read_url", "write_file", "read_file",
        "execute_sql", "send_email", "parse_pdf", "translate",
        "summarize", "analyze_sentiment", "generate_image",
    ],
)
