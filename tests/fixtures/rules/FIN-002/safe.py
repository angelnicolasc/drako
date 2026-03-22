# ok: FIN-002
# Multiple models used — route cheap tasks to cheaper models
import openai

client = openai.OpenAI()

# Complex reasoning -> frontier model
response_analysis = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Perform deep analysis"}],
)

# Simple tasks -> cheaper model
response_classify = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Classify this email"}],
)
