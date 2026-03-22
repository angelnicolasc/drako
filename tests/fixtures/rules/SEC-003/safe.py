# ok: SEC-003
# Tool with filesystem access and proper path validation
from pathlib import Path
from crewai import Agent
from crewai_tools import tool

ALLOWED_DIR = Path("/data/documents")


@tool
def read_document(file_path: str) -> str:
    resolved = Path(file_path).resolve()
    if not str(resolved).startswith(str(ALLOWED_DIR)):
        raise ValueError("Path outside allowed directory")
    with open(resolved, "r") as f:
        return f.read()


agent = Agent(name="reader", tools=[read_document])
