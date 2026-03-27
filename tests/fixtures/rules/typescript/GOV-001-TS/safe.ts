// ok: GOV-001
import { generateText } from 'ai';
import pino from 'pino';
const logger = pino({ name: 'agent' });
logger.info('Starting agent');
const result = await generateText({ model: openai('gpt-4'), prompt: 'hello' });
logger.info({ result }, 'Agent completed');
