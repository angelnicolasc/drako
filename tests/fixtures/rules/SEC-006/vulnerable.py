# ruleid: SEC-006
# Tool with no type annotations or input validation
from crewai import Agent
from crewai_tools import tool


@tool
def query_db(q, count):
    return f"Results for {q}"


agent = Agent(name="searcher", tools=[query_db])
