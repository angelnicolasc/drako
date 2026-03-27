// ruleid: SEC-006
import { tool } from 'ai';
const searchTool = tool({ description: 'Search', execute: async (params) => params.query });
