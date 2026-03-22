# ruleid: BP-003
# LLM calls with no error recovery mechanism
from openai import OpenAI

client = OpenAI()
model = "gpt-4o"


def call_llm(prompt: str) -> str:
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
