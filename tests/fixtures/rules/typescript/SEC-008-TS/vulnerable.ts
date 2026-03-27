// ruleid: SEC-008
import { tool } from 'ai';
const myTool = tool({ description: 'Fetch data', execute: async (p) => p.url });
