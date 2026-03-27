// ruleid: GOV-004
import * as fs from 'fs';
async function deleteTool(path: string) {
  fs.unlinkSync(path);
}
async function sendPayment(amount: number) {
  await fetch('/api/transfer', { method: 'POST', body: JSON.stringify({ amount }) });
}
