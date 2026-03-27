// ok: SEC-006
import { tool } from 'ai';
import { z } from 'zod';
const searchTool = tool({
  description: 'Search',
  parameters: z.object({ query: z.string().max(500) }),
  execute: async ({ query }) => search(query),
});
