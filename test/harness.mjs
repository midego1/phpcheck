// Verdict tests: stub fetch for fake hosts (php.net/endoflife.date go through for real), call the worker, assert verdicts. Run: npm test
let fail = 0;
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
  'nextjs.example':   { status: 200, headers: { server: 'Vercel', 'x-vercel-id': 'ams1::abc', 'x-powered-by': 'Next.js' }, body: '<html><head><script src="/_next/static/chunks/main.js"></script></head></html>' },
  'cdnonly.example':  { status: 200, headers: { server: 'cloudflare', 'cf-ray': 'abc' }, body: '<html><body>hi</body></html>' },
  'wp.example':       { status: 200, headers: { server: 'nginx/1.18.0', 'x-powered-by': 'PHP/8.1.2-1ubuntu2.19', 'set-cookie': 'PHPSESSID=abc; path=/' },
                        body: '<html><head><meta name="generator" content="WordPress 6.4.2"><script src="https://code.jquery.com/jquery-1.12.4.min.js"></script><link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.0.0"><script src="/wp-includes/js/wp-embed.min.js?ver=6.4.2"></script><link href="/wp-content/themes/twentytwentyfour/style.css"></head><body></body></html>' },
  'secure.example':   { status: 200, headers: { server: 'nginx', 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'content-security-policy': "default-src 'self'; frame-ancestors 'none'", 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'permissions-policy': 'camera=()', 'set-cookie': 'sid=1; Secure; HttpOnly; SameSite=Lax' }, body: '<html><body>ok</body></html>' },
};
globalThis.fetch = async (input, init = {}) => {
  const url = typeof input === 'string' ? input : input.url;
  const host = new URL(url).hostname;
  if (!(host in canned)) return realFetch(input, init);
  let c = canned[host];
  if (init.method === 'GET' && c.get) c = c.get;
  return new Response(init.method === 'GET' ? c.body || '' : null, { status: c.status, headers: c.headers });
};
// Wordfence matcher unit test: build the index with the script from a tiny fake feed, serve it as assets
{
  const { execFileSync } = await import('node:child_process');
  const { mkdtempSync, writeFileSync, readFileSync, existsSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const wf = await import(new URL('../src/wordfence.js', import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), 'vuln-'));
  const feed = {};
  // 1,000 filler records so the truncation guard passes
  for (let i = 0; i < 1000; i++) feed['f' + i] = { id: 'f' + i, title: 'filler ' + i, informational: false, software: [{ type: 'plugin', slug: 'zz-filler-' + i, affected_versions: { '* - 1.0': { from_version: '*', from_inclusive: true, to_version: '1.0', to_inclusive: true } }, patched: true, patched_versions: ['1.1'] }] };
  feed.u1 = { id: 'u1', title: 'CF7 XSS', informational: false, published: '2024-01-01 00:00:00', references: ['https://www.wordfence.com/threat-intel/vulnerabilities/x'], cve: 'CVE-2024-0001', cvss: { score: 6.1, rating: 'Medium' },
    software: [{ type: 'plugin', slug: 'contact-form-7', name: 'Contact Form 7', affected_versions: { '* - 5.1.5': { from_version: '*', from_inclusive: true, to_version: '5.1.5', to_inclusive: true } }, patched: true, patched_versions: ['5.1.6'] }] };
  feed.u2 = { id: 'u2', title: 'Core SSRF', informational: false, published: '2022-01-01 00:00:00', references: [], software: [{ type: 'core', slug: 'wordpress', affected_versions: { '6.0 - 6.0.2': { from_version: '6.0', from_inclusive: true, to_version: '6.0.2', to_inclusive: true } }, patched: true, patched_versions: ['6.0.3'] }] };
  feed.u4 = { id: 'u4', title: 'Prototype slug', informational: false, software: [{ type: 'plugin', slug: 'constructor', affected_versions: { '* - 1.0': { from_version: '*', from_inclusive: true, to_version: '1.0', to_inclusive: true } }, patched: true, patched_versions: ['1.1'] }] };
  feed.u3 = { id: 'u3', title: 'Info only', informational: true, software: [{ type: 'plugin', slug: 'contact-form-7', affected_versions: { '*': { from_version: '*', from_inclusive: true, to_version: '*', to_inclusive: true } }, patched: false, patched_versions: [] }] };
  const feedFile = join(dir, 'feed.json'); writeFileSync(feedFile, JSON.stringify(feed));
  const out = join(dir, 'vuln');
  execFileSync(process.execPath, [new URL('../scripts/build-vuln-index.mjs', import.meta.url).pathname, '--from', feedFile, '--out', out], { stdio: 'pipe' });
  const ASSETS = { fetch: async (req) => { const p = join(out, new URL(req.url).pathname.replace(/^\/vuln\//, '')); return existsSync(p) ? new Response(readFileSync(p), { status: 200 }) : new Response('', { status: 404 }); } };
  const env = { ASSETS };
  const t1 = await wf.lookup(env, 'plugin', 'contact-form-7', '5.0.0');
  const t2 = await wf.lookup(env, 'plugin', 'contact-form-7', '5.1.6');
  const t3 = await wf.lookup(env, 'core', 'wordpress', '6.0.1');
  const t4 = await wf.lookup(env, 'core', 'wordpress', '6.0.3');
  const t5 = await wf.lookup(env, 'plugin', 'contact-form-7', null);
  const t6 = await wf.lookup({ ASSETS: { fetch: async () => new Response('', { status: 404 }) } }, 'plugin', 'contact-form-7', '1.0');
  const t7 = await wf.lookup(env, 'plugin', 'constructor', '0.9');
  const t8 = await wf.lookup(env, 'plugin', 'toString', '0.9');
  const meta = JSON.parse(readFileSync(join(out, 'meta.json'), 'utf8'));
  for (const [name, ok] of [
    ['wordfence: index built with meta', meta.entries === 1004 && meta.files >= 3],
    ['wordfence: slug "constructor" indexed and found', t7.length === 1],
    ['wordfence: slug "toString" with no records is empty', t8.length === 0],
    ['wordfence: cf7 5.0.0 affected with CVE and fix, informational excluded', t1.length === 1 && t1[0].fixedIn === '5.1.6' && t1[0].cve === 'CVE-2024-0001' && t1[0].rating === 'Medium'],
    ['wordfence: cf7 5.1.6 clean', t2.length === 0],
    ['wordfence: core 6.0.1 affected', t3.length === 1],
    ['wordfence: core 6.0.3 clean', t4.length === 0],
    ['wordfence: unknown version reports history unconfirmed', t5.length === 1 && t5[0].confirmed === false],
    ['wordfence: missing index yields null, not empty', t6 === null],
  ]) { if (!ok) fail++; console.log(ok ? 'PASS' : 'FAIL', name); }
}
const mod = await import(new URL("../src/index.js", import.meta.url));
const req = new Request('http://x/api/check', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ targets: Object.keys(canned).filter(h => h !== 'www.redirect.example') }) });
const res = await mod.default.fetch(req, { ASSETS: { fetch: () => new Response('') } }, { waitUntil() {} });
const data = await res.json();
if (data.error) { console.log('ERROR', data.error); process.exit(1); }
const expect = { 'latest.example': 'latest', 'outdated.example': 'outdated', 'eol.example': 'eol', 'distro.example': 'distro', 'partial.example': 'partial', 'cookie.example': 'php-no-version', 'redirect.example': 'outdated', 'headonly.example': 'latest', 'body.example': 'php-no-version', 'old.example': 'eol', 'nextjs.example': 'not-php', 'cdnonly.example': 'no-signal', 'wp.example': 'eol', 'secure.example': 'no-signal' };
for (const r of data.results) {
  const ok = r.verdict === expect[r.input];
  if (!ok) fail++;
  console.log((ok ? 'PASS' : 'FAIL'), r.input.padEnd(20), r.verdict.padEnd(16), r.php.version || '-', '| behind:', r.comparison?.patchesBehind ?? '-', '| adv:', r.advisories.map(a => a.id).join(',') || '-', '|', r.findings[0]?.text.slice(0, 90));
}
// Security enrichment assertions
const wp = data.results.find(r => r.input === 'wp.example');
const sec = data.results.find(r => r.input === 'secure.example');
const checks = [
  ['wp: headers grade is D or F', ['D', 'F'].includes(wp.security?.grade)],
  ['wp: PHPSESSID cookie flagged', wp.security?.checks.some(c => c.id === 'cookie:PHPSESSID' && c.status === 'bad')],
  ['wp: jquery 1.12.4 found with vulns', wp.libraries?.some(l => l.name === 'jquery' && l.version === '1.12.4' && l.vulnerabilities.length >= 2)],
  ['wp: WordPress 6.4.2 outdated', wp.cms?.name === 'WordPress' && wp.cms.version === '6.4.2' && wp.cms.status === 'outdated'],
  ['wp: contact-form-7 5.0.0 outdated', wp.cms?.plugins.some(p => p.slug === 'contact-form-7' && p.status === 'outdated' && p.latest)],
  ['wp: nginx 1.18.0 eol', wp.server?.some(s => s.name === 'nginx' && s.status === 'eol')],
  ['secure: headers grade A', sec.security?.grade === 'A'],
  ['secure: no vulnerable libs', (sec.libraries || []).length === 0],
];
for (const [name, ok] of checks) { if (!ok) fail++; console.log(ok ? 'PASS' : 'FAIL', name); }
const o = data.results.find(r => r.input === 'outdated.example');
console.log('\n--- agent prompt (outdated.example), first 40 lines ---');
console.log(o.agentPrompt.split('\n').slice(0, 40).join('\n'));
console.log(fail ? `\n${fail} FAILED` : '\nALL PASS');
process.exit(fail ? 1 : 0);
