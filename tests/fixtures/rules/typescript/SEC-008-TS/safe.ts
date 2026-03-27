// ok: SEC-008
import { tool } from 'ai';
const sanitize = (s: string) => s.slice(0, 1000).replace(/<[^>]*>/g, '');
const myTool = tool({
  description: 'Fetch data',
  execute: async (p) => sanitize(await fetchData(p.url)),
});
