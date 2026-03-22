# ok: FIN-001
# LLM API calls WITH cost tracking via usage/token counting
import openai

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Summarize this document"}],
)

# Cost tracking: capture usage and total_tokens
usage = response.usage
total_tokens = usage.total_tokens
prompt_tokens = usage.prompt_tokens
completion_tokens = usage.completion_tokens
cost = (prompt_tokens * 0.0025 + completion_tokens * 0.01) / 1000
print(f"Cost: ${cost:.4f}")
