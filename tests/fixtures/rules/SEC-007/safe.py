# ok: SEC-007
# Prompt without user input interpolation
system_prompt = "You are a helpful research assistant. Always cite your sources."
messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": "What is the capital of France?"},
]
