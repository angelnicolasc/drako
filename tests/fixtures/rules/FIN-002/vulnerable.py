# ruleid: FIN-002
# Only a single model used for all tasks — no cost optimization routing
import openai

client = openai.OpenAI()

# All tasks use gpt-4o regardless of complexity
response_summary = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Summarize this text"}],
)
response_classify = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Classify this email"}],
)
