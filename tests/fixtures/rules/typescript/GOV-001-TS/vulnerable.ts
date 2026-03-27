// ruleid: GOV-001
import { generateText } from 'ai';
const result = await generateText({ model: openai('gpt-4'), prompt: 'hello' });
