// ok: SEC-003
import * as fs from 'fs';
import * as path from 'path';
const safePath = path.resolve(SANDBOX_DIR, userPath);
if (!safePath.startsWith(SANDBOX_DIR)) throw new Error('Path traversal');
const data = fs.readFileSync(safePath);
