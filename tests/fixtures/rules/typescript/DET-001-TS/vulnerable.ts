// ruleid: DET-001
import OpenAI from 'openai';
const client = new OpenAI();
const res = await client.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello' }],
  temperature: 0.7,
});
