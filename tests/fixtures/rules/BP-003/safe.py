# ok: BP-003
# LLM calls with retry mechanism
from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

client = OpenAI()
model = "gpt-4o"


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def call_llm(prompt: str) -> str:
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
