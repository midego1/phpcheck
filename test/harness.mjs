// Verdict tests: stub fetch for fake hosts (php.net/endoflife.date go through for real), call the worker, assert verdicts. Run: npm test
const realFetch = globalThis.fetch;
globalThis.caches = { default: { match: async () => null, put: async () => {} } };
const canned = {
  'latest.example':   { status: 200, headers: { 'x-powered-by': 'PHP/8.4.27', server: 'nginx' } },
  'outdated.example': { status: 200, headers: { 'x-powered-by': 'PHP/8.4.24', server: 'Apache/2.4.62' } },
  'eol.example':      { status: 200, headers: { 'x-powered-by': 'PHP/8.1.30', server: 'Apache' } },
  'distro.example':   { status: 200, headers: { server: 'Apache/2.4.58 (Ubuntu)', 'x-powered-by': 'PHP/8.3.6-0ubuntu0.24.04.5' } },
  'partial.example':  { status: 200, headers: { 'x-powered-by': 'PHP/8.2' } },
  'cookie.example':   { status: 200, headers: { 'set-cookie': 'PHPSESSID=abc; path=/', server: 'nginx' } },
  'redirect.example': { status: 301, headers: { location: 'https://www.redirect.example/', 'x-powered-by': 'PHP/8.3.35' } },
  'www.redirect.example': { status: 200, headers: { server: 'cloudflare' } },
  'headonly.example': { status: 405, headers: { server: 'nginx' }, get: { status: 200, headers: { 'x-powered-by': 'PHP/8.5.12' } } },
  'body.example':     { status: 200, headers: { server: 'nginx' }, body: '<html><head><meta name="generator" content="WordPress 6.9"></head><body><a href="/index.php?x=1">x</a></body></html>' },
  'old.example':      { status: 200, headers: { 'x-powered-by': 'PHP/5.6.40' } },
};
globalThis.fetch = async (input, init = {}) => {
  const url = typeof input === 'string' ? input : input.url;
  const host = new URL(url).hostname;
  if (!(host in canned)) return realFetch(input, init);
  let c = canned[host];
  if (init.method === 'GET' && c.get) c = c.get;
  return new Response(init.method === 'GET' ? c.body || '' : null, { status: c.status, headers: c.headers });
};
const mod = await import(new URL("../src/index.js", import.meta.url));
const req = new Request('http://x/api/check', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ targets: Object.keys(canned).filter(h => h !== 'www.redirect.example') }) });
const res = await mod.default.fetch(req, { ASSETS: { fetch: () => new Response('') } }, { waitUntil() {} });
const data = await res.json();
if (data.error) { console.log('ERROR', data.error); process.exit(1); }
const expect = { 'latest.example': 'latest', 'outdated.example': 'outdated', 'eol.example': 'eol', 'distro.example': 'distro', 'partial.example': 'partial', 'cookie.example': 'php-no-version', 'redirect.example': 'outdated', 'headonly.example': 'latest', 'body.example': 'php-no-version', 'old.example': 'eol' };
let fail = 0;
for (const r of data.results) {
  const ok = r.verdict === expect[r.input];
  if (!ok) fail++;
  console.log((ok ? 'PASS' : 'FAIL'), r.input.padEnd(20), r.verdict.padEnd(16), r.php.version || '-', '| behind:', r.comparison?.patchesBehind ?? '-', '| adv:', r.advisories.map(a => a.id).join(',') || '-', '|', r.findings[0]?.text.slice(0, 90));
}
const o = data.results.find(r => r.input === 'outdated.example');
console.log('\n--- agent prompt (outdated.example), first 40 lines ---');
console.log(o.agentPrompt.split('\n').slice(0, 40).join('\n'));
console.log(fail ? `\n${fail} FAILED` : '\nALL PASS');
process.exit(fail ? 1 : 0);
