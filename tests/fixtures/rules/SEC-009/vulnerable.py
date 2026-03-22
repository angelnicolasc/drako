# ruleid: SEC-009
# Tool output interpolated directly into prompt variable via f-string
tool_output = "some external result data"
context_prompt = f"Based on the following result: {tool_output}. Summarize this data."
