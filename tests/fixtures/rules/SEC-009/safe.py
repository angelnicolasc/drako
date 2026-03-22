# ok: SEC-009
# Tool output passed as separate message, not interpolated into prompt
system_prompt = "You are a helpful research assistant."
messages = [
    {"role": "system", "content": system_prompt},
    {"role": "tool", "content": "some external result data"},
    {"role": "user", "content": "Summarize the tool output above."},
]
