// ok: SEC-004
const allowedDomains = ['api.openai.com', 'api.anthropic.com'];
const url = new URL(userProvidedUrl);
if (!allowedDomains.includes(url.hostname)) throw new Error('Blocked');
const response = await fetch(url.toString());
