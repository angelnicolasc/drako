// ok: COM-001
import { generateText } from 'ai';
import pino from 'pino';
const logger = pino({ name: 'ai-audit' });
const result = await generateText({ model: openai('gpt-4'), prompt: 'hello' });
logger.info({ input: 'hello', output: result }, 'ai-event');
