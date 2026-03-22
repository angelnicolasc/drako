from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Classify this text: AI is transformative"}],
)
print(response.choices[0].message.content)
