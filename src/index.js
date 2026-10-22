/**
 * php-version-check — Cloudflare Worker
 *
 * GET  /api/releases            -> supported PHP branches, latest patch, EOL dates (cached 6h)
 * GET  /api/check?target=host   -> single check
 * POST /api/check {targets:[]}  -> bulk check (max 20 per request; the UI chunks larger lists)
 * POST /api/import {provider, token, teamId?} -> list domains from a Cloudflare or Vercel account (token used once, never stored)
 * POST /mcp                     -> MCP server (Streamable HTTP, stateless JSON responses)
 * /*                            -> static UI from ./public
 */

const UA = 'php-version-check/0.1 (passive header check; HEAD/GET of the homepage only)';
const PHPNET_ACTIVE = 'https://www.php.net/releases/active.php';
const ENDOFLIFE = 'https://endoflife.date/api/php.json';
const MAX_TARGETS = 20;
const CONCURRENCY = 5;
const FETCH_TIMEOUT_MS = 6000;
const MAX_REDIRECTS = 5;
const BODY_BYTES = 65536;

// Named advisories worth calling out by CVE. Keyed by branch -> first fixed version.
const ADVISORIES = [
  {
    id: 'PHP-2026-10-21',
    title: 'Critical security release of 21 Oct 2026: CVE-2026-109618 (RCE via OOM corruption) and CVE-2026-109619 (RCE via stale global state), both CVSS 4.0 9.2',
    url: 'https://www.php.net/archive/2026.php#2026-10-21-1',
    fixed: { '8.5': '8.5.12', '8.4': '8.4.27', '8.3': '8.3.36', '8.2': '8.2.35' },
  },
];

// Rate limiting: Workers Rate Limiting bindings keyed by client IP. When a binding is
// missing (older wrangler, local dev without support) the check is skipped, not failed.
async function rateLimited(env, name, request) {
  const binding = env[name];
  if (!binding || typeof binding.limit !== 'function') return false;
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
  try {
    const { success } = await binding.limit({ key: ip });
    return !success;
  } catch {
    return false;
  }
}

const RL_LIMITS = { RL_CHECK: '30 requests per minute', RL_IMPORT: '10 requests per minute', RL_MCP: '60 requests per minute' };

function tooMany(name) {
  return json({ error: `Rate limit exceeded: ${RL_LIMITS[name]} per IP. Try again in a minute.` }, 429, { 'retry-after': '60' });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/api/releases') {
        return json(await getReleases(ctx));
      }
      if (url.pathname === '/api/check') {
        if (await rateLimited(env, 'RL_CHECK', request)) return tooMany('RL_CHECK');
        let targets = [];
        if (request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          targets = Array.isArray(body.targets) ? body.targets : [];
        } else {
          targets = url.searchParams.getAll('target');
        }
        targets = targets.map((t) => String(t || '').trim()).filter(Boolean);
        if (targets.length === 0) return json({ error: 'No targets given' }, 400);
        if (targets.length > MAX_TARGETS) {
          return json({ error: `Max ${MAX_TARGETS} targets per request; the UI chunks larger lists.` }, 400);
        }
        const releases = await getReleases(ctx);
        const results = await pool(targets, CONCURRENCY, (t) => checkTarget(t, releases));
        return json({ checkedAt: new Date().toISOString(), releases: summarizeReleases(releases), results });
      }
      if (url.pathname === '/api/import') {
        if (request.method !== 'POST') return json({ error: 'POST only' }, 405);
        if (await rateLimited(env, 'RL_IMPORT', request)) return tooMany('RL_IMPORT');
        const body = await request.json().catch(() => ({}));
        return json(await importDomains(body));
      }
      if (url.pathname.startsWith('/api/')) return json({ error: 'Not found' }, 404);
      if (url.pathname === '/mcp') return handleMcp(request, env, ctx);
      return env.ASSETS.fetch(request);
    } catch (err) {
      return json({ error: String(err && err.message ? err.message : err) }, 500);
    }
  },
};

// ---------------------------------------------------------------------------
// Release data
// ---------------------------------------------------------------------------

let memo = null; // { at, data } per isolate, in case the Cache API is cold

async function getReleases(ctx) {
  if (memo && Date.now() - memo.at < 60 * 60 * 1000) return memo.data;
  const cache = caches.default;
  const key = new Request('https://php-version-check.internal/releases-v1');
  const hit = await cache.match(key).catch(() => null);
  if (hit) {
    const data = await hit.json();
    memo = { at: Date.now(), data };
    return data;
  }

  const [phpnet, eol] = await Promise.all([
    fetch(PHPNET_ACTIVE, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
      .then((r) => (r.ok ? r.json() : null))
      .catch(() => null),
    fetch(ENDOFLIFE, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
      .then((r) => (r.ok ? r.json() : null))
      .catch(() => null),
  ]);

  const branches = {};
  if (Array.isArray(eol)) {
    for (const c of eol) {
      branches[c.cycle] = {
        branch: c.cycle,
        latest: c.latest || null,
        latestDate: c.latestReleaseDate || null,
        activeSupportUntil: c.support || null,
        eol: c.eol || null,
        source: 'endoflife.date',
      };
    }
  }
  if (phpnet && typeof phpnet === 'object') {
    for (const major of Object.values(phpnet)) {
      for (const [b, info] of Object.entries(major || {})) {
        const fromFile = info?.source?.[0]?.filename?.match(/php-(\d+\.\d+\.\d+)/)?.[1];
        const v = info?.version || fromFile || null;
        branches[b] = {
          ...(branches[b] || { branch: b }),
          latest: v,
          latestDate: info?.date || branches[b]?.latestDate || null,
          latestTags: Array.isArray(info?.tags) ? info.tags : [],
          supportedByPhpNet: true,
          source: branches[b] ? 'php.net + endoflife.date' : 'php.net',
        };
      }
    }
  }
  const today = new Date().toISOString().slice(0, 10);
  for (const b of Object.values(branches)) {
    b.status = branchStatus(b, today);
  }

  const data = {
    fetchedAt: new Date().toISOString(),
    sources: { phpnet: !!phpnet, endoflife: Array.isArray(eol) },
    branches,
  };
  if (!phpnet && !Array.isArray(eol)) throw new Error('Could not load release data from php.net or endoflife.date');

  memo = { at: Date.now(), data };
  const res = new Response(JSON.stringify(data), {
    headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=21600' },
  });
  ctx.waitUntil(cache.put(key, res).catch(() => {}));
  return data;
}

function branchStatus(b, today) {
  if (b.eol && b.eol <= today) return 'eol';
  if (b.activeSupportUntil && b.activeSupportUntil <= today) return 'security';
  if (b.supportedByPhpNet || b.eol) return 'active';
  return 'unknown';
}

function summarizeReleases(rel) {
  const out = {};
  for (const [k, b] of Object.entries(rel.branches)) {
    if (b.status === 'eol' && !b.supportedByPhpNet && k < '7') continue; // keep the table short
    out[k] = b;
  }
  return { fetchedAt: rel.fetchedAt, sources: rel.sources, branches: out };
}

// ---------------------------------------------------------------------------
// Target checking
// ---------------------------------------------------------------------------

function normalizeTarget(raw) {
  let s = raw.trim();
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try {
    u = new URL(s);
  } catch {
    return { error: 'Not a valid hostname or URL' };
  }
  const host = u.hostname.toLowerCase();
  if (!host.includes('.') && host !== 'localhost') return { error: 'Not a valid hostname' };
  if (isPrivateHost(host)) return { error: 'Private, local or reserved hosts are not checked' };
  const path = u.pathname && u.pathname !== '/' ? u.pathname : '/';
  return { host, path, scheme: u.protocol.replace(':', '') };
}

function isPrivateHost(host) {
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return true;
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  if (host.includes(':')) return true; // IPv6 literal: skip rather than parse
  return false;
}

async function checkTarget(raw, releases) {
  const started = Date.now();
  const norm = normalizeTarget(raw);
  const result = {
    input: raw,
    host: norm.host || null,
    verdict: 'unreachable',
    php: { detected: false, version: null, branch: null, source: null, raw: null, distroBuild: false },
    http: { attempts: [], finalUrl: null, status: null, redirects: [] },
    headers: {},
    signals: [],
    findings: [],
    branchInfo: null,
    comparison: null,
    advisories: [],
    agentPrompt: null,
    ms: 0,
  };
  if (norm.error) {
    result.verdict = 'invalid';
    result.findings.push(f('bad', norm.error));
    result.ms = Date.now() - started;
    return result;
  }

  // 1. HEAD over https, then http if https failed at the network level.
  const schemes = norm.scheme === 'http' ? ['http', 'https'] : ['https', 'http'];
  let chain = null;
  let chainMethod = 'HEAD';
  for (const scheme of schemes) {
    const start = `${scheme}://${norm.host}${norm.path}`;
    let r = await fetchChain(start, 'HEAD');
    result.http.attempts.push({ url: start, method: 'HEAD', ok: !r.error, error: r.error || null, status: r.final?.status ?? null });
    if (r.error && /timed out/i.test(r.error)) {
      // Some servers silently drop HEAD; try a GET on the same scheme before giving up on it.
      r = await fetchChain(start, 'GET');
      result.http.attempts.push({ url: start, method: 'GET', ok: !r.error, error: r.error || null, status: r.final?.status ?? null });
      if (!r.error) chainMethod = 'GET';
    }
    if (!r.error) {
      chain = r;
      break;
    }
  }
  if (!chain) {
    result.findings.push(f('bad', `Could not connect over https or http: ${result.http.attempts.map((a) => a.error).join(' / ')}`));
    result.findings.push(f('info', 'Nothing could be inspected. Check DNS, firewall rules or whether the host only answers on a non-standard port.'));
    result.agentPrompt = buildAgentPrompt(result, releases);
    result.ms = Date.now() - started;
    return result;
  }

  // 2. If HEAD was refused or the response carries no useful headers, GET the final URL.
  let final = chain.final;
  let body = '';
  const headRefused = final.status === 405 || final.status === 501 || final.status === 403 || final.status === 400 || final.status >= 500;
  const headSignals = extractSignals(chain.hops);
  if (chainMethod === 'GET') {
    body = chain.body || '';
    result.findings.push(f('info', 'HEAD requests time out on this server; GET was used instead.'));
  } else if (headRefused || !headSignals.phpVersion) {
    const g = await fetchChain(chain.hops[chain.hops.length - 1].url, 'GET', 2);
    result.http.attempts.push({ url: chain.hops[chain.hops.length - 1].url, method: 'GET', ok: !g.error, error: g.error || null, status: g.final?.status ?? null });
    if (!g.error) {
      body = g.body || '';
      // Merge: keep the redirect hops from HEAD, replace the final hop with the GET response.
      chain = { hops: [...chain.hops.slice(0, -1), ...g.hops], final: g.final };
      final = g.final;
    }
  }

  result.http.finalUrl = chain.hops[chain.hops.length - 1].url;
  result.http.status = final.status;
  result.http.redirects = chain.hops.slice(0, -1).map((h) => ({ from: h.url, status: h.status, to: h.location }));
  result.headers = chain.hops[chain.hops.length - 1].headers;

  // 3. Signals
  const sig = extractSignals(chain.hops, body);
  result.signals = sig.list;

  if (sig.phpVersion) {
    result.php.detected = true;
    result.php.version = sig.phpVersion.version;
    result.php.raw = sig.phpVersion.raw;
    result.php.source = sig.phpVersion.source;
    result.php.distroBuild = sig.phpVersion.distroBuild;
    result.php.branch = sig.phpVersion.version.split('.').slice(0, 2).join('.');
    if (sig.phpVersion.hop !== null && sig.phpVersion.hop < chain.hops.length - 1) {
      result.findings.push(f('info', `The version was exposed by a redirect hop (${chain.hops[sig.phpVersion.hop].url}), not by the final page.`));
    }
  } else if (sig.phpLikely) {
    result.php.detected = true;
  }

  // 4. Compare against releases
  evaluate(result, releases);

  result.agentPrompt = buildAgentPrompt(result, releases);
  result.ms = Date.now() - started;
  return result;
}

async function fetchChain(startUrl, method, maxRedirects = MAX_REDIRECTS) {
  const hops = [];
  let current = startUrl;
  let m = method;
  for (let i = 0; i <= maxRedirects; i++) {
    let res;
    try {
      res = await fetch(current, {
        method: m,
        redirect: 'manual',
        headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml,*/*;q=0.8', 'accept-language': 'en' },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch (e) {
      return { error: shortError(e), hops };
    }
    const hop = { url: current, status: res.status, headers: headersToObject(res.headers), location: null };
    hops.push(hop);
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) return { hops, final: res };
      let next;
      try {
        next = new URL(loc, current).toString();
      } catch {
        return { hops, final: res };
      }
      hop.location = next;
      const nextHost = new URL(next).hostname.toLowerCase();
      if (isPrivateHost(nextHost)) return { hops, final: res, error: 'Redirected to a private host' };
      if (res.status === 303) m = 'GET';
      current = next;
      await res.body?.cancel().catch(() => {});
      continue;
    }
    let body = '';
    if (m === 'GET') {
      body = await readPrefix(res, BODY_BYTES);
    } else {
      await res.body?.cancel().catch(() => {});
    }
    return { hops, final: res, body };
  }
  return { error: `More than ${maxRedirects} redirects`, hops };
}

async function readPrefix(res, limit) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let got = 0;
  try {
    while (got < limit) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
      got += value.length;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  const buf = new Uint8Array(got);
  let o = 0;
  for (const c of chunks) {
    buf.set(c, o);
    o += c.length;
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(0, limit));
}

function headersToObject(h) {
  const out = {};
  for (const [k, v] of h.entries()) {
    out[k] = out[k] ? `${out[k]}, ${v}` : v;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Signal extraction
// ---------------------------------------------------------------------------

const PHP_VERSION_RE = /PHP\/(\d+\.\d+(?:\.\d+)?)([A-Za-z0-9.+~_-]*)/i;

function extractSignals(hops, body = '') {
  const list = [];
  let phpVersion = null;
  let phpLikely = false;

  hops.forEach((hop, idx) => {
    const h = hop.headers;
    const isFinal = idx === hops.length - 1;
    const where = isFinal ? 'final response' : `redirect hop ${idx + 1}`;

    for (const name of ['x-powered-by', 'server', 'x-php-version']) {
      const val = h[name];
      if (!val) continue;
      const m = val.match(PHP_VERSION_RE);
      if (m) {
        const suffix = m[2] || '';
        const distro = /ubuntu|debian|deb|el\d|fc\d|\+|~/i.test(suffix);
        const cand = { version: m[1], raw: val, source: name, hop: idx, distroBuild: distro, suffix };
        // Prefer the final hop, and prefer a full x.y.z over x.y
        if (!phpVersion || (isFinal && phpVersion.hop !== idx) || (m[1].split('.').length > phpVersion.version.split('.').length)) {
          phpVersion = cand;
        }
        list.push(sig('version', name, val, where, `PHP ${m[1]}${suffix ? ' (' + suffix.replace(/^-/, '') + ')' : ''} exposed in the ${name} header`));
      } else if (/php/i.test(val)) {
        phpLikely = true;
        list.push(sig('php', name, val, where, `${name} header mentions PHP without a version`));
      } else if (name === 'x-powered-by' && /statamic|laravel|symfony|codeigniter|cakephp|yii|slim|craft|nette|phalcon|typo3|magento|wordpress|drupal|joomla|shopware|prestashop|opencart|pimcore|silverstripe|plesk/i.test(val)) {
        phpLikely = true;
        list.push(sig('php', name, val, where, `x-powered-by reports ${val}, a PHP framework/CMS; version not exposed`));
      }
    }

    if (h['x-powered-by'] && !/php/i.test(h['x-powered-by'])) {
      list.push(sig('stack', 'x-powered-by', h['x-powered-by'], where, `x-powered-by reports ${h['x-powered-by']}`));
    }
    if (h['server']) {
      const s = h['server'];
      const label = /cloudflare/i.test(s)
        ? 'Served through Cloudflare; origin headers are usually passed through, but a Cloudflare-side rule may strip them'
        : /litespeed/i.test(s)
        ? 'LiteSpeed server (commonly paired with PHP on shared hosting)'
        : /nginx|apache|openresty|caddy|iis|envoy|varnish|gws|awselb|akamai/i.test(s)
        ? `Server header: ${s}`
        : `Server header: ${s}`;
      list.push(sig('server', 'server', s, where, label));
    }
    for (const name of ['via', 'x-cache', 'x-served-by', 'x-cdn', 'x-vercel-id', 'x-amz-cf-id', 'x-github-request-id', 'fly-request-id', 'x-render-origin-server']) {
      if (h[name]) list.push(sig('proxy', name, h[name], where, `Proxy/CDN layer present (${name}); it may strip or rewrite origin headers`));
    }
    if (h['set-cookie'] && /PHPSESSID=/i.test(h['set-cookie'])) {
      phpLikely = true;
      list.push(sig('php', 'set-cookie', 'PHPSESSID=…', where, 'PHPSESSID cookie: the app runs on PHP, version not exposed'));
    }
    if (h['x-generator']) {
      if (/wordpress|drupal|joomla|typo3|magento|craft|laravel|symfony|shopware|prestashop|concrete/i.test(h['x-generator'])) phpLikely = true;
      list.push(sig('cms', 'x-generator', h['x-generator'], where, `x-generator: ${h['x-generator']}`));
    }
    if (h['x-pingback'] || /api\.w\.org/.test(h['link'] || '')) {
      phpLikely = true;
      list.push(sig('cms', h['x-pingback'] ? 'x-pingback' : 'link', h['x-pingback'] || 'rel="https://api.w.org/"', where, 'WordPress markers present; WordPress always runs on PHP'));
    }
    if (h['x-aspnet-version'] || /asp\.net/i.test(h['x-powered-by'] || '')) {
      list.push(sig('stack', 'x-aspnet-version', h['x-aspnet-version'] || h['x-powered-by'], where, 'ASP.NET markers: this site is probably not PHP'));
    }
    if (h['x-drupal-cache'] || h['x-drupal-dynamic-cache']) {
      phpLikely = true;
      list.push(sig('cms', 'x-drupal-cache', h['x-drupal-cache'] || h['x-drupal-dynamic-cache'], where, 'Drupal markers present; Drupal runs on PHP'));
    }
    if (h['x-magento-cache-debug'] || h['x-magento-vary']) {
      phpLikely = true;
      list.push(sig('cms', 'x-magento', 'present', where, 'Magento markers present; Magento runs on PHP'));
    }
    if (h['x-shopify-stage'] || h['x-shopid']) {
      list.push(sig('stack', 'x-shopify', 'present', where, 'Shopify storefront: hosted platform, not PHP'));
    }
    if (h['x-wix-request-id']) list.push(sig('stack', 'x-wix-request-id', 'present', where, 'Wix: hosted platform, not PHP'));
    if (h['x-sc-rewrite'] || /squarespace/i.test(h['server'] || '')) list.push(sig('stack', 'server', h['server'], where, 'Squarespace: hosted platform, not PHP'));
  });

  if (body) {
    const gen = body.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i) || body.match(/<meta\s+content=["']([^"']+)["']\s+name=["']generator["']/i);
    if (gen) {
      const g = gen[1];
      if (/wordpress|drupal|joomla|typo3|magento|craft|laravel|symfony|shopware|prestashop|concrete|opencart|moodle|mediawiki|nextcloud|phpbb|wix|squarespace|hugo|jekyll|gatsby|next\.js|nuxt|ghost|webflow/i.test(g)) {
        if (!/wix|squarespace|hugo|jekyll|gatsby|next\.js|nuxt|ghost|webflow/i.test(g)) phpLikely = true;
        list.push(sig('cms', 'html meta generator', g, 'page body', `Generator meta tag: ${g}`));
      }
    }
    if (/\/wp-content\/|\/wp-includes\/|wp-json/i.test(body)) {
      phpLikely = true;
      if (!list.some((s) => /WordPress/i.test(s.text))) list.push(sig('cms', 'html body', '/wp-content/', 'page body', 'WordPress asset paths in the HTML; WordPress runs on PHP'));
    }
    const phpLinks = body.match(/href=["'][^"']*\.php(\?[^"']*)?["']/gi);
    if (phpLinks && phpLinks.length) {
      phpLikely = true;
      list.push(sig('php', 'html body', `${phpLinks.length} link(s) to .php URLs`, 'page body', `${phpLinks.length} link(s) to .php files in the HTML`));
    }
  }

  return { list, phpVersion, phpLikely };
}

function sig(kind, header, value, where, text) {
  return { kind, header, value: String(value).slice(0, 300), where, text };
}

// ---------------------------------------------------------------------------
// Evaluation against release data
// ---------------------------------------------------------------------------

function evaluate(result, releases) {
  const branches = releases.branches;
  const php = result.php;
  const supported = Object.values(branches).filter((b) => b.status !== 'eol' && b.latest).map((b) => `${b.branch} → ${b.latest}`);

  if (result.http.status >= 400) {
    result.findings.push(f('warn', `The final response was HTTP ${result.http.status}; headers were still inspected but the page may not be the real site.`));
  }

  if (!php.detected) {
    result.verdict = 'no-signal';
    result.findings.push(f('info', 'No PHP marker found in response headers or the first 64 KB of HTML.'));
    result.findings.push(f('info', 'This usually means one of: PHP with expose_php=Off and no PHP-specific cookies on the homepage, a non-PHP stack, or a CDN/proxy that strips origin headers.'));
    if (result.signals.some((s) => s.kind === 'stack')) {
      result.findings.push(f('info', 'Other stack markers were found; see Signals. The site may simply not run PHP.'));
    }
    return;
  }

  if (!php.version) {
    result.verdict = 'php-no-version';
    result.findings.push(f('ok', 'PHP is in use, but the version is not exposed. That is the recommended configuration (expose_php=Off).'));
    result.findings.push(f('info', `Only an inside check can confirm the patch level. Supported branches right now: ${supported.join(', ')}.`));
    return;
  }

  const branch = php.branch;
  const info = branches[branch] || null;
  result.branchInfo = info;
  const detParts = php.version.split('.').map(Number);
  const hasPatch = detParts.length === 3;

  if (!info) {
    result.verdict = 'eol';
    result.findings.push(f('bad', `PHP ${php.version} is on branch ${branch}, which is not in the release data at all. Treat it as end-of-life.`));
    return;
  }

  const latestParts = (info.latest || '').split('.').map(Number);
  const cmp = hasPatch && latestParts.length === 3 ? compareVersions(detParts, latestParts) : null;
  result.comparison = {
    detected: php.version,
    latestOnBranch: info.latest,
    latestDate: info.latestDate || null,
    patchesBehind: cmp === null ? null : Math.max(0, latestParts[2] - detParts[2]),
    branchStatus: info.status,
    activeSupportUntil: info.activeSupportUntil || null,
    eol: info.eol || null,
    newestBranch: newestBranch(branches),
  };

  // Advisories
  for (const adv of ADVISORIES) {
    const fixed = adv.fixed[branch];
    if (fixed && hasPatch && compareVersions(detParts, fixed.split('.').map(Number)) < 0) {
      result.advisories.push({ id: adv.id, title: adv.title, url: adv.url, fixedIn: fixed });
    }
    if (!fixed && info.status === 'eol') {
      result.advisories.push({ id: adv.id, title: adv.title + ' — this EOL branch is presumed affected and no fix will be published for it', url: adv.url, fixedIn: null });
    }
  }

  if (info.status === 'eol') {
    result.verdict = 'eol';
    result.findings.push(f('bad', `Branch ${branch} reached end-of-life on ${info.eol}. No security fixes are published for it any more.`));
  } else if (php.distroBuild) {
    result.verdict = 'distro';
    result.findings.push(f('warn', `This is a distribution build (${php.raw}). Debian/Ubuntu/RHEL backport security fixes without bumping the version number, so "${php.version}" may already contain the fixes from ${info.latest}. Only the package changelog can tell.`));
  } else if (cmp === null) {
    result.verdict = 'partial';
    result.findings.push(f('warn', `Only the branch (${php.version}) is exposed, not the patch level. Latest on this branch is ${info.latest}.`));
  } else if (cmp >= 0) {
    result.verdict = 'latest';
    result.findings.push(f('ok', `PHP ${php.version} is the latest release on branch ${branch} (released ${info.latestDate || 'n/a'}).`));
  } else {
    result.verdict = 'outdated';
    const behind = result.comparison.patchesBehind;
    const secTag = Array.isArray(info.latestTags) && info.latestTags.includes('security');
    result.findings.push(
      f('bad', `PHP ${php.version} is ${behind} patch release${behind === 1 ? '' : 's'} behind ${info.latest} (released ${info.latestDate || 'n/a'}${secTag ? ', tagged security' : ''}).`)
    );
  }

  if (info.status === 'security') {
    result.findings.push(f('warn', `Branch ${branch} is in security-only support until ${info.eol}. Plan the move to ${result.comparison.newestBranch}.`));
  } else if (info.status === 'active') {
    result.findings.push(f('info', `Branch ${branch} has active support until ${info.activeSupportUntil || 'n/a'} and security support until ${info.eol || 'n/a'}.`));
  }
  for (const adv of result.advisories) {
    result.findings.push(f('bad', `Affected by ${adv.id}: ${adv.title}.${adv.fixedIn ? ` Fixed in ${adv.fixedIn}.` : ''}`));
  }
  if (php.version && result.verdict !== 'latest') {
    result.findings.push(f('info', 'Exposing the PHP version in headers is itself a finding: set expose_php=Off in php.ini after patching.'));
  } else if (php.version) {
    result.findings.push(f('info', 'The version is exposed in headers. Consider expose_php=Off; it does not improve security much, but removes a free fingerprint.'));
  }
}

function newestBranch(branches) {
  return Object.values(branches)
    .filter((b) => b.status === 'active' && b.latest)
    .map((b) => b.branch)
    .sort((a, b) => compareVersions(a.split('.').map(Number), b.split('.').map(Number)))
    .pop() || null;
}

function compareVersions(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] || 0;
    const y = b[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function f(level, text) {
  return { level, text };
}

// ---------------------------------------------------------------------------
// Agent prompt
// ---------------------------------------------------------------------------

function buildAgentPrompt(r, releases) {
  const branches = Object.values(releases.branches).filter((b) => b.status !== 'eol' && b.latest);
  const table = branches
    .sort((a, b) => compareVersions(a.branch.split('.').map(Number), b.branch.split('.').map(Number)))
    .map((b) => `  - ${b.branch}: latest ${b.latest} (${b.latestDate || 'date n/a'}), ${b.status === 'active' ? 'active support until ' + b.activeSupportUntil : 'security-only'}, EOL ${b.eol}`)
    .join('\n');
  const newest = newestBranch(releases.branches);
  const host = r.host || r.input;
  const c = r.comparison;
  const php = r.php;

  const observed = [];
  observed.push(`- Checked: ${r.http.finalUrl || r.input} (HTTP ${r.http.status ?? 'no response'})`);
  if (r.http.redirects.length) observed.push(`- Redirects: ${r.http.redirects.map((x) => `${x.from} -> ${x.status}`).join(', ')}`);
  if (php.version) observed.push(`- PHP version exposed: ${php.version} via ${php.source} header (raw: "${php.raw}")${php.distroBuild ? ' — distribution build' : ''}`);
  else if (php.detected) observed.push('- PHP detected (markers present) but the version is hidden');
  else observed.push('- No PHP markers found in headers or HTML');
  for (const s of r.signals) observed.push(`- Signal: ${s.text} [${s.header}: ${s.value}]`);
  for (const x of r.findings) observed.push(`- ${x.level.toUpperCase()}: ${x.text}`);

  let goal;
  if (r.verdict === 'latest') goal = `Confirm from inside the server that ${host} really runs PHP ${php.version} everywhere (CLI and web SAPI can differ) and that no other vhost or container on the same host runs an older PHP.`;
  else if (r.verdict === 'outdated') goal = `Upgrade PHP on ${host} from ${php.version} to ${c.latestOnBranch} (same branch, drop-in patch release), then verify.`;
  else if (r.verdict === 'eol') goal = `Migrate ${host} off PHP ${php.version} (branch ${php.branch} is end-of-life) to PHP ${newest}, with a compatibility pass first.`;
  else if (r.verdict === 'distro') goal = `Determine whether the distribution package providing PHP ${php.version} on ${host} already contains the fixes from ${c.latestOnBranch}; if not, update it or switch to an upstream-tracking repository.`;
  else if (r.verdict === 'partial') goal = `Find the exact patch level of PHP ${php.version} on ${host} and bring it to ${c.latestOnBranch} if it is behind.`;
  else if (r.verdict === 'php-no-version') goal = `Find the exact PHP version behind ${host} from inside the server and confirm it is the latest patch on a supported branch.`;
  else if (r.verdict === 'unreachable' || r.verdict === 'invalid') goal = `Establish why ${host} could not be reached by an external HTTP check, then determine its PHP version from inside.`;
  else goal = `Determine whether ${host} runs PHP at all, and if so which version, from inside the server.`;

  const steps = [];
  steps.push(`1. CHECK — find the PHP version actually serving web requests.
   - SSH in (or open the hosting panel). Run: php -v ; php-fpm -v (or php-fpm8.x -v) ; ls /etc/php/ ; which php
   - CLI and web SAPI often differ. Confirm the web one: put a temporary file <?php echo PHP_VERSION; ?> in the docroot, curl it, delete it. On Docker: docker exec <container> php -v and inspect the image tag.
   - Shared hosting (cPanel/Plesk/DirectAdmin): read the PHP selector / "PHP Settings" for this domain; the version per domain can differ from the server default.
   - List every site on the host; one outdated vhost is enough to compromise the box.`);
  steps.push(`2. CONFIRM — compare with the current releases below. Report: detected version, branch, latest on that branch, how many patches behind, branch support status, and whether any listed advisory applies. If the version string has a distro suffix (e.g. 8.1.2-1ubuntu2.19), read the package changelog (apt changelog php8.1-fpm | head -80, or rpm -q --changelog php-fpm | head -40) and state which CVEs it already includes instead of trusting the number.`);
  if (r.verdict === 'eol') {
    steps.push(`3. FIX — branch upgrade (not a drop-in):
   - Run a compatibility scan first: composer require --dev phpcompatibility/php-compatibility squizlabs/php_codesniffer, then phpcs -p --standard=PHPCompatibility --runtime-set testVersion ${newest} ./ ; or use Rector with the level-set for PHP ${newest}.
   - Check every extension and framework version supports PHP ${newest} (composer why-not php ${newest}).
   - Do it on staging first, run the test suite, then production. Keep the old binary installed until verified.`);
  } else if (r.verdict === 'distro') {
    steps.push(`3. FIX — distribution package:
   - Debian/Ubuntu: apt update && apt list --upgradable | grep php ; apt install --only-upgrade 'php${php.branch}*' ; then re-check the changelog for the CVE ids.
   - If the distro has not shipped the fix, switch to the Ondřej Surý repository (ppa:ondrej/php on Ubuntu, packages.sury.org on Debian) or Remi on RHEL/Alma/Rocky, which track upstream patch releases.
   - Restart the service: systemctl restart php${php.branch}-fpm (and apache2 if mod_php).`);
  } else {
    steps.push(`3. FIX — patch release on the same branch (drop-in, no code changes expected):
   - Debian/Ubuntu with Surý packages: apt update && apt install --only-upgrade 'php${php.branch || '8.x'}*'
   - RHEL/Alma/Rocky with Remi: dnf update 'php*'
   - Docker: bump the base image tag to php:${c?.latestOnBranch || php.branch || '8.x'}-fpm (or -apache), rebuild, redeploy.
   - cPanel/Plesk: update via the panel's PHP management (EasyApache / Plesk Installer) and re-select the version per domain.
   - Managed hosts (Kinsta, WP Engine, Cloudways, Laravel Forge, Platform.sh…): change the PHP version in the dashboard; the patch level is controlled by the host, so open a ticket if it lags.
   - Restart php-fpm / the web server afterwards.`);
  }
  steps.push(`4. VERIFY — after the change:
   - Inside: php -v and the web SAPI test file again; both must show the target version.
   - Outside: curl -sI ${r.http.finalUrl || 'https://' + host} | grep -i -E 'x-powered-by|server'
   - Run the application's smoke tests / open the main pages; check the PHP error log for new deprecation notices.
   - Then set expose_php = Off in php.ini (and remove any "Header set X-Powered-By") so the version is no longer advertised; restart and re-run the curl to confirm the header is gone.`);
  steps.push(`5. REPORT back in this format: host, before version, after version, branch status, advisories closed, header exposure (on/off), anything left open.`);

  const advisories = r.advisories.length
    ? `\nAdvisories that apply:\n${r.advisories.map((a) => `  - ${a.id}: ${a.title}${a.fixedIn ? ` (fixed in ${a.fixedIn})` : ''} — ${a.url}`).join('\n')}\n`
    : '';

  return `You are a careful sysadmin agent. Work on the server(s) behind ${host}. Do not change anything in production without a backup/snapshot and without confirming on staging first when a branch upgrade is involved. Never set expose_php=On; it is not needed for any check below.

GOAL
${goal}

WHAT AN EXTERNAL PASSIVE CHECK SAW (${r.checkedAt || new Date().toISOString().slice(0, 10)})
${observed.join('\n')}

CURRENT PHP RELEASES (php.net, as of ${releases.fetchedAt.slice(0, 10)})
${table}
${advisories}
STEPS
${steps.join('\n\n')}

CONSTRAINTS
- Only touch what is needed for the PHP version; log every command you run.
- If the server is managed by a third party, produce the ticket text instead of changing things yourself.
- Stop and ask if the application has no test suite and the change is a branch upgrade.`;
}

// ---------------------------------------------------------------------------
// Account import: list domains from Cloudflare (zones) or Vercel (project domains).
// The token is used for these listing requests only and is never stored or logged.
// ---------------------------------------------------------------------------

const IMPORT_MAX_PAGES = 20;

async function importDomains(body) {
  const provider = String(body.provider || '').toLowerCase();
  const token = String(body.token || '').trim();
  if (!token) return { error: 'No token given' };
  if (token.length > 512) return { error: 'Token looks wrong (too long)' };
  if (provider === 'cloudflare') return importCloudflare(token);
  if (provider === 'vercel') return importVercel(token, String(body.teamId || '').trim());
  return { error: 'Unknown provider; use "cloudflare" or "vercel"' };
}

async function apiGet(url, token) {
  const res = await fetch(url, { headers: { authorization: `Bearer ${token}`, 'user-agent': UA, accept: 'application/json' }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  let data = null;
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data };
}

async function importCloudflare(token) {
  // No separate verify call: /user/tokens/verify only accepts user-owned tokens, and
  // account-owned tokens are just as valid for listing zones. The zones call reports errors itself.
  const domains = [];
  const accounts = new Set();
  let total = null;
  let truncated = false;
  for (let page = 1; page <= IMPORT_MAX_PAGES; page++) {
    const r = await apiGet(`https://api.cloudflare.com/client/v4/zones?per_page=50&page=${page}`, token);
    if (!r.data || r.data.success === false) {
      const msg = r.data?.errors?.map((e) => e.message).join('; ') || `HTTP ${r.status}`;
      const hint = r.status === 400 || r.status === 401 || r.status === 403
        ? ' Create a token at dash.cloudflare.com → My Profile → API Tokens (or Account → API Tokens) with permission "Zone · Zone · Read" for all zones, and paste it without surrounding spaces.'
        : '';
      return { error: `Cloudflare could not list zones: ${msg}.${hint}` };
    }
    for (const z of r.data.result || []) {
      domains.push({ domain: z.name, source: 'cloudflare', account: z.account?.name || null, status: z.status, plan: z.plan?.name || null });
      if (z.account?.name) accounts.add(z.account.name);
    }
    const info = r.data.result_info || {};
    if (info.total_count) total = info.total_count;
    if (!info.total_pages || page >= info.total_pages) break;
    if (page === IMPORT_MAX_PAGES && info.total_pages > IMPORT_MAX_PAGES) truncated = true;
  }
  return { provider: 'cloudflare', accounts: [...accounts], count: domains.length, total: total ?? domains.length, truncated, domains, ...(truncated ? { warning: `Only the first ${domains.length} of ${total} zones were listed (page limit of ${IMPORT_MAX_PAGES * 50}).` } : {}) };
}

async function importVercel(token, teamId) {
  const team = teamId ? (teamId.startsWith('team_') ? `&teamId=${encodeURIComponent(teamId)}` : `&slug=${encodeURIComponent(teamId)}`) : '';
  const seen = new Map();
  let vercelTruncated = false;
  let partialReason = '';
  let note = '';
  let until = '';
  for (let page = 1; page <= IMPORT_MAX_PAGES; page++) {
    const r = await apiGet(`https://api.vercel.com/v9/projects?limit=100${team}${until}`, token);
    if (r.status === 401 || r.status === 403) {
      const msg = r.data?.error?.message || `HTTP ${r.status}`;
      return { error: `Vercel rejected the token: ${msg}. Create one at vercel.com/account/tokens; for a team, add the team slug or ID.` };
    }
    if (!r.data || !Array.isArray(r.data.projects)) return { error: `Could not list Vercel projects (HTTP ${r.status})` };
    for (const p of r.data.projects) {
      const aliases = new Set();
      for (const a of p.targets?.production?.alias || []) aliases.add(a);
      for (const d of p.latestDeployments || []) for (const a of d.alias || []) aliases.add(a);
      for (const a of aliases) {
        const host = String(a).toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
        if (!host || host.endsWith('.vercel.app') || host.endsWith('.now.sh')) continue;
        if (!seen.has(host)) seen.set(host, { domain: host, source: 'vercel', project: p.name, framework: p.framework || null });
      }
    }
    const next = r.data.pagination?.next;
    if (!next) break;
    if (page === IMPORT_MAX_PAGES) vercelTruncated = true;
    until = `&until=${next}`;
  }
  // Domains added to the account/team but not attached to a project's production alias (paginated too)
  let dUntil = '';
  for (let page = 1; page <= IMPORT_MAX_PAGES; page++) {
    const d = await apiGet(`https://api.vercel.com/v5/domains?limit=100${team}${dUntil}`, token);
    if (!d.data || !Array.isArray(d.data.domains)) {
      // The first page is optional (some tokens cannot list account domains) but is still reported;
      // a failed later page means the list is partial.
      if (page > 1) { vercelTruncated = true; partialReason = `domain page ${page} failed (HTTP ${d.status})`; }
      else note = `Account domain list unavailable (HTTP ${d.status}); only domains attached to projects were listed.`;
      break;
    }
    for (const x of d.data.domains) {
      const host = String(x.name || '').toLowerCase();
      if (host && !seen.has(host)) seen.set(host, { domain: host, source: 'vercel', project: null, framework: null });
    }
    const next = d.data.pagination?.next;
    if (!next) break;
    if (page === IMPORT_MAX_PAGES) vercelTruncated = true;
    dUntil = `&until=${next}`;
  }
  const domains = [...seen.values()];
  const warning = partialReason
    ? `The domain list is incomplete: ${partialReason}. Add the remaining domains by hand or retry.`
    : `Only the first ${IMPORT_MAX_PAGES * 100} projects or domains were listed; add the remaining domains by hand.`;
  return { provider: 'vercel', count: domains.length, truncated: vercelTruncated, domains, ...(vercelTruncated ? { warning } : {}), ...(note ? { note } : {}) };
}

// ---------------------------------------------------------------------------
// MCP (Streamable HTTP transport, stateless: every POST is answered with JSON)
// ---------------------------------------------------------------------------

const MCP_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_TOOLS = [
  {
    name: 'check_php_version',
    title: 'Check PHP version of websites',
    description:
      'Passively reads the PHP version one or more websites expose (X-Powered-By / Server headers and CMS markers), compares it with the current php.net releases and returns a verdict per site (latest, outdated, eol, distro, partial, php-no-version, no-signal, unreachable), the evidence, applicable advisories and a ready-made check/confirm/fix prompt. Only the homepage is requested. Max 20 targets per call.',
    inputSchema: {
      type: 'object',
      properties: {
        targets: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: MAX_TARGETS, description: 'Domains or URLs, e.g. ["example.com", "https://shop.example.org/"]' },
      },
      required: ['targets'],
    },
  },
  {
    name: 'php_releases',
    title: 'Current PHP releases',
    description: 'Returns the supported PHP branches with their latest patch release, release date, support status (active / security / eol) and end-of-life dates, from php.net and endoflife.date.',
    inputSchema: { type: 'object', properties: {} },
  },
];

const MCP_CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
  'access-control-allow-headers': 'content-type, mcp-session-id, mcp-protocol-version, authorization',
  'access-control-expose-headers': 'mcp-session-id, mcp-protocol-version',
};

async function handleMcp(request, env, ctx) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: MCP_CORS });
  if (request.method === 'POST' && (await rateLimited(env, 'RL_MCP', request))) {
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32000, message: `Rate limit exceeded: ${RL_LIMITS.RL_MCP} per IP. Try again in a minute.` } }), {
      status: 429,
      headers: { ...MCP_CORS, 'content-type': 'application/json; charset=utf-8', 'retry-after': '60' },
    });
  }
  if (request.method === 'DELETE') return new Response(null, { status: 200, headers: MCP_CORS });
  if (request.method === 'GET') {
    return new Response(JSON.stringify({ name: 'php-check', transport: 'streamable-http', note: 'POST JSON-RPC 2.0 messages to this URL. Server-initiated streams (GET/SSE) are not used.' }), {
      status: 405,
      headers: { ...MCP_CORS, allow: 'POST, DELETE, OPTIONS', 'content-type': 'application/json' },
    });
  }
  if (request.method !== 'POST') return new Response(null, { status: 405, headers: { ...MCP_CORS, allow: 'POST, DELETE, OPTIONS' } });

  let body;
  try {
    body = await request.json();
  } catch {
    return mcpJson({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400);
  }
  const msgs = Array.isArray(body) ? body : [body];
  const responses = [];
  for (const m of msgs) {
    if (!m || m.jsonrpc !== '2.0' || typeof m.method !== 'string') {
      responses.push({ jsonrpc: '2.0', id: m?.id ?? null, error: { code: -32600, message: 'Invalid Request' } });
      continue;
    }
    const isNotification = m.id === undefined || m.id === null;
    try {
      const result = await mcpDispatch(m, ctx);
      if (!isNotification) responses.push({ jsonrpc: '2.0', id: m.id, result });
    } catch (e) {
      if (!isNotification) responses.push({ jsonrpc: '2.0', id: m.id, error: { code: e.code || -32603, message: e.message || 'Internal error' } });
    }
  }
  if (responses.length === 0) return new Response(null, { status: 202, headers: MCP_CORS });
  return mcpJson(Array.isArray(body) ? responses : responses[0]);
}

function mcpJson(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...MCP_CORS, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
}

function rpcError(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

async function mcpDispatch(m, ctx) {
  const p = m.params || {};
  switch (m.method) {
    case 'initialize': {
      const requested = typeof p.protocolVersion === 'string' ? p.protocolVersion : null;
      return {
        protocolVersion: MCP_VERSIONS.includes(requested) ? requested : MCP_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'php-check', title: 'PHP Check', version: '0.1.0' },
        instructions:
          'Use check_php_version with one or more domains to learn which PHP version a site exposes and whether it is the latest patch for its branch. Most well-configured hosts hide the version; the result then says "php-no-version" or "no-signal", which is expected, not an error. Each result carries an agentPrompt with concrete check/confirm/fix steps.',
      };
    }
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null;
    case 'ping':
      return {};
    case 'tools/list':
      return { tools: MCP_TOOLS };
    case 'tools/call':
      return mcpCallTool(p.name, p.arguments || {}, ctx);
    case 'resources/list':
      return { resources: [] };
    case 'prompts/list':
      return { prompts: [] };
    default:
      throw rpcError(-32601, `Method not found: ${m.method}`);
  }
}

async function mcpCallTool(name, args, ctx) {
  if (name === 'php_releases') {
    const rel = summarizeReleases(await getReleases(ctx));
    return { content: [{ type: 'text', text: JSON.stringify(rel, null, 2) }], structuredContent: rel };
  }
  if (name === 'check_php_version') {
    const targets = Array.isArray(args.targets) ? args.targets.map((t) => String(t || '').trim()).filter(Boolean) : [];
    if (targets.length === 0) return { isError: true, content: [{ type: 'text', text: 'Give at least one target in "targets".' }] };
    if (targets.length > MAX_TARGETS) return { isError: true, content: [{ type: 'text', text: `Max ${MAX_TARGETS} targets per call.` }] };
    const releases = await getReleases(ctx);
    const results = await pool(targets, CONCURRENCY, (t) => checkTarget(t, releases));
    const out = { checkedAt: new Date().toISOString(), results };
    const lines = results.map((r) => {
      const v = r.php?.version ? `PHP ${r.php.version}` + (r.comparison?.latestOnBranch ? ` (latest on branch: ${r.comparison.latestOnBranch})` : '') : r.php?.detected ? 'PHP, version hidden' : 'no PHP signal';
      return `${r.host || r.input}: ${r.verdict} — ${v}${r.advisories?.length ? ` — ${r.advisories.length} advisory(ies) apply` : ''}`;
    });
    return {
      content: [
        { type: 'text', text: lines.join('\n') },
        { type: 'text', text: JSON.stringify(out, null, 2) },
      ],
      structuredContent: out,
    };
  }
  throw rpcError(-32602, `Unknown tool: ${name}`);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function pool(items, size, fn) {
  const out = new Array(items.length);
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const idx = i++;
      try {
        out[idx] = await fn(items[idx]);
      } catch (e) {
        out[idx] = { input: items[idx], verdict: 'unreachable', findings: [f('bad', `Internal error: ${shortError(e)}`)], php: { detected: false }, http: { attempts: [], redirects: [] }, signals: [], headers: {}, advisories: [] };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, worker));
  return out;
}

function shortError(e) {
  const m = String(e && e.message ? e.message : e);
  if (/timeout|aborted/i.test(m)) return `timed out after ${FETCH_TIMEOUT_MS / 1000}s`;
  return m.slice(0, 200);
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'access-control-allow-origin': '*', ...extra },
  });
}
