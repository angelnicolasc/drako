// ok: GOV-004
async function deleteTool(path: string) {
  const approved = await askUserApproval(`Delete ${path}?`);
  if (!approved) throw new Error('Not approved');
  fs.unlinkSync(path);
}
