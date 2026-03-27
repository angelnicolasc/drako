// ok: GOV-005
import OpenAI from 'openai';
import pRetry from 'p-retry';
const client = new OpenAI();
const res = await pRetry(() => client.chat.completions.create({ model: 'gpt-4', messages: [] }), { retries: 3 });
