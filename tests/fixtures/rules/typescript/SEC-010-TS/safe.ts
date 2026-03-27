// ok: SEC-010
import { generateText } from 'ai';
import { PromptGuard } from '@company/guardrails';
const guard = new PromptGuard();
const checked = await guard.check(userMessage);
const result = await generateText({ model: openai('gpt-4'), prompt: checked });
