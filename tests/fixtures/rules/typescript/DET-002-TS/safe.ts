// ok: DET-002
import OpenAI from 'openai';
const client = new OpenAI({ timeout: 30000 });
const res = await client.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello' }],
  timeout: 30000,
});
