// ok: ODD-001
import { generateText } from 'ai';
const allowedTools = [searchTool, calcTool];
const result = await generateText({ model: openai('gpt-4'), tools: allowedTools, maxSteps: 10 });
