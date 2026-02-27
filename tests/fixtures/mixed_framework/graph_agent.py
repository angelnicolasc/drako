"""LangGraph agent in a mixed-framework project."""
from typing import TypedDict
from langgraph.graph import StateGraph, END


class PipelineState(TypedDict):
    input_data: str
    output: str


def process_node(state: PipelineState) -> PipelineState:
    """Process the input data."""
    return {"input_data": state["input_data"], "output": "processed"}


graph = StateGraph(PipelineState)
graph.add_node("process", process_node)
graph.add_edge("process", END)
graph.set_entry_point("process")
pipeline = graph.compile()
