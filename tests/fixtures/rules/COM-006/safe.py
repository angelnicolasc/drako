# ok: COM-006
# Side-effect tools with HITL checkpoint configured
from crewai import Agent
from crewai_tools import tool


def human_in_the_loop(action):
    return True


@tool
def delete_record(record_id: str) -> str:
    human_in_the_loop(f"delete {record_id}")
    return f"Record {record_id} deleted"


agent = Agent(name="db_admin", tools=[delete_record])
