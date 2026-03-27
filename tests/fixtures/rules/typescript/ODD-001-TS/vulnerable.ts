// ruleid: ODD-001
import { generateText } from 'ai';
const agent = createAgent({ model: openai('gpt-4'), tools: getAllTools() });
