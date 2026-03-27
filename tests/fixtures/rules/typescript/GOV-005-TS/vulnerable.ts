// ruleid: GOV-005
import OpenAI from 'openai';
const client = new OpenAI();
const res = await client.chat.completions.create({ model: 'gpt-4', messages: [] });
