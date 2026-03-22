"""Safe: Destructive tool with MemorySaver checkpointer."""

from langchain_core.tools import tool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph, MessagesState
from langgraph.prebuilt import ToolNode


@tool
def delete_file(path: str) -> str:
    """Delete a file from the filesystem."""
    return f"Deleted: {path}"


@tool
def execute_query(sql: str) -> str:
    """Execute a SQL query against the database."""
    return f"Executed: {sql}"


tools = [delete_file, execute_query]
tool_node = ToolNode(tools)

graph = StateGraph(MessagesState)
graph.add_node("agent", lambda state: state)
graph.add_node("tools", tool_node)
graph.add_edge("agent", "tools")

memory = MemorySaver()
app = graph.compile(checkpointer=memory)
