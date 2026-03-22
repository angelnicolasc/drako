# ruleid: COM-006
# Side-effect tools without checkpoint for human review
from crewai import Agent
from crewai_tools import tool


@tool
def delete_record(record_id: str) -> str:
    return f"Record {record_id} deleted"


@tool
def update_database(query: str) -> str:
    return f"Database updated: {query}"


agent = Agent(name="db_admin", tools=[delete_record, update_database])
