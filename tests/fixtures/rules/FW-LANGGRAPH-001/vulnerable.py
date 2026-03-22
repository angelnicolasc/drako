"""Vulnerable: ToolNode without any human approval gate."""

from langchain_core.tools import tool
from langgraph.graph import StateGraph, MessagesState
from langgraph.prebuilt import ToolNode


@tool
def search_web(query: str) -> str:
    """Search the web for information."""
    return f"Results for: {query}"


tools = [search_web]
tool_node = ToolNode(tools)

graph = StateGraph(MessagesState)
graph.add_node("agent", lambda state: state)
graph.add_node("tools", tool_node)
graph.add_edge("agent", "tools")

app = graph.compile()
