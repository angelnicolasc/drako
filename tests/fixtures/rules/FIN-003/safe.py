# ok: FIN-003
# LLM calls with caching layer configured
import openai
from functools import lru_cache

client = openai.OpenAI()


@lru_cache(maxsize=256)
def answer_question(question: str) -> str:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": question}],
    )
    return response.choices[0].message.content

# Repeated queries are served from cache
answer_question("What is the capital of France?")
answer_question("What is the capital of France?")  # cache hit
