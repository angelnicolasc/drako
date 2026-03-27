// ruleid: SEC-003
import * as fs from 'fs';
const data = fs.readFileSync(userPath);
fs.writeFileSync(outputPath, result);
