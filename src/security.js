import { lookup as wfLookup } from './wordfence.js';

/**
 * Security enrichment for a checked site. Everything here works on the response that
 * checkTarget already fetched (headers + first 64 KB of HTML); the only extra requests go to
 * public metadata APIs (Retire.js database, endoflife.date, api.wordpress.org, optional WPScan),
 * never to the checked site.
 */

const UA = 'php-version-check/0.1 (passive header check; HEAD/GET of the homepage only)';
const TIMEOUT_MS = 8000;
const RETIRE_URL = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json';
const WP_CORE_URL = 'https://api.wordpress.org/core/version-check/1.7/';
const MAX_PLUGINS = 15;

const memo = new Map(); // key -> { at, data }

async function cachedJson(ctx, key, url, ttlSeconds, headers = {}) {
  const m = memo.get(key);
  if (m && Date.now() - m.at < Math.min(ttlSeconds, 3600) * 1000) return m.data;
  const cache = caches.default;
  const req = new Request(`https://php-version-check.internal/${key}`);
  const hit = await cache.match(req).catch(() => null);
  if (hit) {
    const data = await hit.json();
    memo.set(key, { at: Date.now(), data });
    return data;
  }
  let data = null;
  try {
    const res = await fetch(url, { headers: { 'user-agent': UA, accept: 'application/json', ...headers }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    data = res.ok ? await res.json() : { __status: res.status };
  } catch {
    data = { __error: true };
  }
  memo.set(key, { at: Date.now(), data });
  ctx.waitUntil(cache.put(req, new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${ttlSeconds}` } })).catch(() => {}));
  return data;
}

// ---------------------------------------------------------------------------
// Version helpers
// ---------------------------------------------------------------------------

export function cmpVer(a, b) {
  const pa = String(a).split(/[.\-+]/).filter((x) => x !== '');
  const pb = String(b).split(/[.\-+]/).filter((x) => x !== '');
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? '0';
    const y = pb[i] ?? '0';
    const nx = /^\d+$/.test(x) ? Number(x) : null;
    const ny = /^\d+$/.test(y) ? Number(y) : null;
    if (nx !== null && ny !== null) {
      if (nx !== ny) return nx < ny ? -1 : 1;
    } else if (nx !== null) return 1; // numeric > prerelease tag
    else if (ny !== null) return -1;
    else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// 1. Security headers and cookies
// ---------------------------------------------------------------------------

const SESSION_COOKIE = /^(phpsessid|laravel_session|wordpress_(logged_in|sec)|wp-settings|ci_session|jsessionid|connect\.sid|sessionid|session|_session_id|asp\.net_sessionid|__session|sid|csrf.*|xsrf-token)$/i;

export function analyzeHeaders(headers, setCookies, isHttps) {
  const checks = [];
  const add = (id, name, status, value, advice) => checks.push({ id, name, status, value: value == null ? null : String(value).slice(0, 200), advice });
  const h = headers || {};

  if (isHttps) {
    const hsts = h['strict-transport-security'];
    if (!hsts) add('hsts', 'Strict-Transport-Security', 'bad', null, 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" so browsers never downgrade to http.');
    else {
      const age = Number((hsts.match(/max-age=(\d+)/i) || [])[1] || 0);
      if (age < 15552000) add('hsts', 'Strict-Transport-Security', 'warn', hsts, 'max-age is below 180 days; use at least 15552000, preferably 31536000.');
      else if (!/includesubdomains/i.test(hsts)) add('hsts', 'Strict-Transport-Security', 'info', hsts, 'Present. Consider includeSubDomains once every subdomain serves https.');
      else add('hsts', 'Strict-Transport-Security', 'ok', hsts, null);
    }
  } else {
    add('https', 'HTTPS', 'bad', 'final URL is http', 'The site served the final page over plain http. Redirect everything to https.');
  }

  const csp = h['content-security-policy'];
  if (!csp) add('csp', 'Content-Security-Policy', 'warn', null, 'No CSP. Start with a report-only policy and tighten script-src; it blocks most injected-script attacks.');
  else {
    const loose = [];
    if (/unsafe-inline/i.test(csp)) loose.push("'unsafe-inline'");
    if (/unsafe-eval/i.test(csp)) loose.push("'unsafe-eval'");
    if (/script-src[^;]*\*/i.test(csp) || /default-src[^;]*\s\*/i.test(csp)) loose.push('wildcard source');
    if (loose.length) add('csp', 'Content-Security-Policy', 'warn', csp, `Present but weakened by ${loose.join(', ')}. Use nonces or hashes instead.`);
    else add('csp', 'Content-Security-Policy', 'ok', csp, null);
  }

  const xfo = h['x-frame-options'];
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !frameAncestors) add('framing', 'Clickjacking protection', 'bad', null, 'Neither X-Frame-Options nor CSP frame-ancestors is set; the site can be framed. Add "X-Frame-Options: SAMEORIGIN" or "frame-ancestors \'self\'".');
  else add('framing', 'Clickjacking protection', 'ok', xfo || 'CSP frame-ancestors', null);

  const xcto = h['x-content-type-options'];
  if (!xcto || !/nosniff/i.test(xcto)) add('nosniff', 'X-Content-Type-Options', 'warn', xcto || null, 'Add "X-Content-Type-Options: nosniff" to stop MIME sniffing of uploads and scripts.');
  else add('nosniff', 'X-Content-Type-Options', 'ok', xcto, null);

  const rp = h['referrer-policy'];
  if (!rp) add('referrer', 'Referrer-Policy', 'warn', null, 'Add "Referrer-Policy: strict-origin-when-cross-origin" so URLs with tokens or IDs do not leak to third parties.');
  else if (/unsafe-url|^no-referrer-when-downgrade$/i.test(rp.trim())) add('referrer', 'Referrer-Policy', 'warn', rp, 'Policy leaks full URLs cross-origin; prefer strict-origin-when-cross-origin.');
  else add('referrer', 'Referrer-Policy', 'ok', rp, null);

  const pp = h['permissions-policy'];
  if (!pp) add('permissions', 'Permissions-Policy', 'info', null, 'Optional: "Permissions-Policy: camera=(), microphone=(), geolocation=()" disables browser features the site does not use.');
  else add('permissions', 'Permissions-Policy', 'ok', pp, null);

  if (h['x-powered-by']) add('powered-by', 'X-Powered-By', 'info', h['x-powered-by'], 'Remove it; it advertises the stack and version for free.');

  const cookies = (setCookies || []).map(parseCookie).filter(Boolean);
  for (const c of cookies.slice(0, 12)) {
    const sessionLike = SESSION_COOKIE.test(c.name) || /sess|auth|token|login/i.test(c.name);
    const problems = [];
    if (isHttps && !c.secure) problems.push('no Secure');
    if (!c.httpOnly && sessionLike) problems.push('no HttpOnly');
    if (!c.sameSite) problems.push('no SameSite');
    if (problems.length) {
      add(`cookie:${c.name}`, `Cookie ${c.name}`, sessionLike && (problems.includes('no Secure') || problems.includes('no HttpOnly')) ? 'bad' : 'warn', problems.join(', '), `Set ${problems.map((p) => p.replace('no ', '')).join(', ')} on this cookie${sessionLike ? '; it looks like a session or auth cookie' : ''}.`);
    } else add(`cookie:${c.name}`, `Cookie ${c.name}`, 'ok', 'Secure, HttpOnly, SameSite', null);
  }

  let score = 100;
  for (const c of checks) {
    if (c.status === 'bad') score -= 20;
    else if (c.status === 'warn') score -= 8;
  }
  score = Math.max(0, score);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';
  return { grade, score, checks, cookies: cookies.length };
}

function parseCookie(raw) {
  const parts = String(raw).split(';').map((s) => s.trim());
  const [nameValue, ...attrs] = parts;
  const eq = nameValue.indexOf('=');
  if (eq <= 0) return null;
  const name = nameValue.slice(0, eq).trim();
  const flags = attrs.map((a) => a.toLowerCase());
  return {
    name,
    secure: flags.includes('secure'),
    httpOnly: flags.includes('httponly'),
    sameSite: (flags.find((a) => a.startsWith('samesite=')) || '').split('=')[1] || null,
  };
}

// ---------------------------------------------------------------------------
// 2. JavaScript libraries (Retire.js database, URL and filename extractors only)
// ---------------------------------------------------------------------------

let retireCompiled = null;

async function loadRetire(ctx) {
  const db = await cachedJson(ctx, 'retire-v4', RETIRE_URL, 86400);
  if (!db || db.__status || db.__error) return null;
  if (retireCompiled && retireCompiled.src === db) return retireCompiled.entries;
  const entries = [];
  const V = '[0-9][0-9.a-z_\\-]+?'; // lazy, so 'jquery-1.12.4.min.js' yields 1.12.4, not 1.12.4.min
  for (const [name, entry] of Object.entries(db)) {
    if (name === 'retire-example' || name === 'dont check') continue;
    const ex = entry.extractors || {};
    const compile = (list) => (list || []).map((p) => { try { return new RegExp(p.replace(/§§version§§/g, '(' + V + ')')); } catch { return null; } }).filter(Boolean);
    const uri = compile(ex.uri);
    const filename = compile(ex.filename);
    if (!uri.length && !filename.length) continue;
    entries.push({ name, uri, filename, vulnerabilities: entry.vulnerabilities || [] });
  }
  retireCompiled = { src: db, entries };
  return entries;
}

function versionFromMatch(m) {
  // The version group is the first capturing group that looks like a version.
  for (let i = 1; i < m.length; i++) if (m[i] && /^\d/.test(m[i])) return m[i];
  return null;
}

export async function findLibraries(body, finalUrl, ctx) {
  const entries = await loadRetire(ctx);
  if (!entries || !body) return { libraries: [], dbLoaded: !!entries };
  const urls = new Set();
  const re = /<(?:script|link)\b[^>]*?(?:src|href)=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(body)) && urls.size < 80) {
    let u = m[1].trim();
    if (!/\.(js|css)(\?|$)/i.test(u)) continue;
    try { u = new URL(u, finalUrl).toString(); } catch { continue; }
    urls.add(u);
  }
  const found = new Map();
  for (const u of urls) {
    const file = u.split('?')[0].split('/').pop() || '';
    for (const e of entries) {
      let version = null;
      for (const r of e.uri) { const mm = u.match(r); if (mm) { version = versionFromMatch(mm); if (version) break; } }
      if (!version) for (const r of e.filename) { const mm = file.match(r); if (mm) { version = versionFromMatch(mm); if (version) break; } }
      if (!version) continue;
      const key = `${e.name}@${version}`;
      if (found.has(key)) continue;
      const vulns = e.vulnerabilities.filter((v) => (!v.below || cmpVer(version, v.below) < 0) && (!v.atOrAbove || cmpVer(version, v.atOrAbove) >= 0)).map((v) => ({
        severity: v.severity || 'unknown',
        summary: v.identifiers?.summary || null,
        cve: v.identifiers?.CVE || [],
        ghsa: v.identifiers?.githubID || null,
        fixedIn: v.below || null,
        info: (v.info || []).slice(0, 3),
      }));
      found.set(key, { name: e.name, version, url: u, vulnerabilities: vulns });
    }
  }
  return { libraries: [...found.values()], dbLoaded: true };
}

// ---------------------------------------------------------------------------
// 3. CMS core and plugins
// ---------------------------------------------------------------------------

export function detectCms(body, headers) {
  if (!body) return null;
  const gen = (body.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i) || body.match(/<meta\s+content=["']([^"']+)["']\s+name=["']generator["']/i) || [])[1] || '';
  const h = headers || {};
  let cms = null;

  if (/wordpress/i.test(gen) || /\/wp-content\/|\/wp-includes\//i.test(body) || /api\.w\.org/.test(h['link'] || '')) {
    const core = (gen.match(/WordPress\s+(\d+\.\d+(?:\.\d+)?)/i) || [])[1] || mostCommon([...body.matchAll(/\/wp-includes\/[^"'\s>]+?\?ver=(\d+\.\d+(?:\.\d+)?)/gi)].map((x) => x[1])) || null;
    const plugins = new Map();
    // A plugin's ?ver= is only trustworthy when it looks like a release number: not a date (20240116),
    // not a hash, and not just the WordPress core version echoed on every asset.
    const looksLikeVersion = (v) => /^\d{1,4}(\.\d{1,5}){1,3}$/.test(v) && v !== core;
    for (const x of body.matchAll(/\/wp-content\/plugins\/([a-z0-9_.-]+)\/[^"'\s>]*?(?:\?|&amp;|&)ver=([0-9][0-9a-z.\-]*)/gi)) {
      const slug = x[1].toLowerCase();
      if (plugins.size >= MAX_PLUGINS) break;
      if (!plugins.get(slug)) plugins.set(slug, looksLikeVersion(x[2]) ? x[2] : plugins.get(slug) || null);
    }
    for (const x of body.matchAll(/\/wp-content\/plugins\/([a-z0-9_.-]+)\//gi)) {
      const slug = x[1].toLowerCase();
      if (!plugins.has(slug) && plugins.size < MAX_PLUGINS) plugins.set(slug, null);
    }
    const theme = (body.match(/\/wp-content\/themes\/([a-z0-9_.-]+)\//i) || [])[1] || null;
    cms = { name: 'WordPress', version: core, plugins: [...plugins].map(([slug, version]) => ({ slug, version })), theme };
  } else if (/drupal/i.test(gen) || h['x-drupal-cache'] || h['x-generator']?.match(/drupal/i)) {
    const v = ((gen || h['x-generator'] || '').match(/Drupal\s+(\d+(?:\.\d+)*)/i) || [])[1] || null;
    cms = { name: 'Drupal', version: v, plugins: [], theme: null };
  } else if (/joomla/i.test(gen)) {
    cms = { name: 'Joomla', version: (gen.match(/(\d+\.\d+(?:\.\d+)?)/) || [])[1] || null, plugins: [], theme: null };
  } else if (/typo3/i.test(gen)) {
    cms = { name: 'TYPO3', version: (gen.match(/(\d+\.\d+(?:\.\d+)?)/) || [])[1] || null, plugins: [], theme: null };
  }
  return cms;
}

function mostCommon(arr) {
  const c = new Map();
  for (const v of arr) c.set(v, (c.get(v) || 0) + 1);
  return [...c].sort((a, b) => b[1] - a[1])[0]?.[0] || null;
}

export async function enrichCms(cms, env, ctx) {
  if (!cms) return null;
  const out = { ...cms, latest: null, status: 'unknown', advisories: [] };
  let feedUsed = false;
  if (cms.name === 'WordPress') {
    const core = await cachedJson(ctx, 'wp-core', WP_CORE_URL, 21600);
    out.latest = core?.offers?.[0]?.version || null;
    if (cms.version && out.latest) out.status = cmpVer(cms.version, out.latest) >= 0 ? 'latest' : (cms.version.split('.').slice(0, 2).join('.') === out.latest.split('.').slice(0, 2).join('.') ? 'outdated-patch' : 'outdated');
    out.plugins = await Promise.all(cms.plugins.map(async (p) => {
      const info = await cachedJson(ctx, `wp-plugin-${p.slug}`, `https://api.wordpress.org/plugins/info/1.0/${encodeURIComponent(p.slug)}.json?fields=-sections,-screenshots,-banners,-icons,-ratings,-tags,-contributors,-description`, 86400);
      const r = { ...p, latest: null, status: 'unknown', lastUpdated: null, testedUpTo: null, vulnerabilities: [] };
      if (info && !info.__status && !info.__error && info.version) {
        r.latest = info.version;
        r.lastUpdated = info.last_updated || null;
        r.testedUpTo = info.tested || null;
        r.name = info.name || p.slug;
        if (p.version) r.status = cmpVer(p.version, info.version) >= 0 ? 'latest' : 'outdated';
      } else if (info && info.__status === 404) {
        r.status = 'not-in-directory';
      }
      const vulns = await wfLookup(env, 'plugin', p.slug, p.version);
      if (vulns) { r.vulnerabilities = vulns; feedUsed = true; }
      return r;
    }));
    if (cms.version) {
      const core = await wfLookup(env, 'core', 'wordpress', cms.version);
      if (core) { out.advisories = core; feedUsed = true; }
    }
    if (cms.theme) {
      const tv = await wfLookup(env, 'theme', cms.theme, null);
      if (tv) { out.themeVulnerabilities = tv.filter((v) => !v.patched).slice(0, 5); feedUsed = true; }
    }
    out.vulnFeed = feedUsed ? 'wordfence' : null;
  } else if (cms.name === 'Drupal' && cms.version) {
    const eol = await cachedJson(ctx, 'eol-drupal', 'https://endoflife.date/api/drupal.json', 21600);
    if (Array.isArray(eol)) {
      const major = cms.version.split('.')[0];
      const cycles = eol.filter((c) => String(c.cycle).split('.')[0] === major);
      const newest = eol[0];
      out.latest = newest?.latest || null;
      if (!cycles.length) out.status = 'eol';
      else {
        const today = new Date().toISOString().slice(0, 10);
        const supported = cycles.some((c) => c.eol === false || (typeof c.eol === 'string' && c.eol > today));
        out.status = supported ? (cms.version.split('.').length >= 2 && cycles.some((c) => c.latest === cms.version) ? 'latest' : 'supported') : 'eol';
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// 4. Server software from the Server header
// ---------------------------------------------------------------------------

const SERVER_PRODUCTS = [
  { re: /\bApache\/(\d+\.\d+(?:\.\d+)?)([^\s]*)/i, name: 'Apache httpd', slug: 'apache-http-server', cycleLen: 2 },
  { re: /\bnginx\/(\d+\.\d+(?:\.\d+)?)/i, name: 'nginx', slug: 'nginx', cycleLen: 2 },
  { re: /\bOpenSSL\/(\d+\.\d+(?:\.\d+)?[a-z]?)/i, name: 'OpenSSL', slug: 'openssl', cycleLen: 2 },
  { re: /\bMicrosoft-IIS\/(\d+\.\d+)/i, name: 'IIS', slug: null, cycleLen: 2 },
  { re: /\bLiteSpeed\b/i, name: 'LiteSpeed', slug: null, cycleLen: 0 },
  { re: /\bopenresty\/(\d+\.\d+\.\d+(?:\.\d+)?)/i, name: 'OpenResty', slug: null, cycleLen: 3 },
  { re: /\bcaddy\b/i, name: 'Caddy', slug: null, cycleLen: 0 },
];

export async function analyzeServer(headers, ctx) {
  const server = (headers || {})['server'];
  if (!server) return [];
  const out = [];
  for (const p of SERVER_PRODUCTS) {
    const m = server.match(p.re);
    if (!m) continue;
    const version = m[1] || null;
    const distro = /ubuntu|debian|centos|red hat|rhel|fedora|alma|rocky/i.test(server) && /apache|nginx|openssl/i.test(p.name);
    const item = { name: p.name, version, raw: server.slice(0, 120), cycle: null, latest: null, eol: null, status: version ? 'unknown' : 'no-version', distroBuild: distro };
    if (version && p.slug) {
      const eol = await cachedJson(ctx, `eol-${p.slug}`, `https://endoflife.date/api/${p.slug}.json`, 21600);
      if (Array.isArray(eol)) {
        const cycle = version.split('.').slice(0, p.cycleLen).join('.');
        const c = eol.find((x) => String(x.cycle) === cycle);
        const today = new Date().toISOString().slice(0, 10);
        item.cycle = cycle;
        if (!c) {
          item.status = 'eol';
          item.latest = eol[0]?.latest || null;
        } else {
          item.latest = c.latest || null;
          item.eol = c.eol === false ? null : c.eol;
          const dead = typeof c.eol === 'string' && c.eol <= today;
          if (dead) item.latest = eol[0]?.latest || c.latest || null;
          item.status = dead ? 'eol' : (c.latest && cmpVer(version, c.latest) < 0 ? (distro ? 'distro' : 'outdated') : 'latest');
        }
      }
    }
    out.push(item);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Orchestration + findings
// ---------------------------------------------------------------------------

export async function enrichSecurity(result, body, setCookies, env, ctx) {
  const isHttps = /^https:/i.test(result.http.finalUrl || '');
  const f = (level, text) => result.findings.push({ level, text });

  result.security = analyzeHeaders(result.headers, setCookies, isHttps);
  const bad = result.security.checks.filter((c) => c.status === 'bad');
  const warn = result.security.checks.filter((c) => c.status === 'warn');
  if (bad.length) f('bad', `Security headers grade ${result.security.grade}: ${bad.map((c) => c.name).join(', ')} missing or unsafe.`);
  else if (warn.length) f('warn', `Security headers grade ${result.security.grade}: ${warn.map((c) => c.name).join(', ')} could be tightened.`);
  else f('ok', `Security headers grade ${result.security.grade}.`);

  const [libs, cms, server] = await Promise.all([
    findLibraries(body, result.http.finalUrl, ctx),
    enrichCms(detectCms(body, result.headers), env, ctx),
    analyzeServer(result.headers, ctx),
  ]);

  result.libraries = libs.libraries;
  const vulnLibs = libs.libraries.filter((l) => l.vulnerabilities.length);
  for (const l of vulnLibs) {
    const worst = ['critical', 'high', 'medium', 'low'].find((s) => l.vulnerabilities.some((v) => v.severity === s)) || 'unknown';
    f(worst === 'critical' || worst === 'high' ? 'bad' : 'warn', `${l.name} ${l.version} has ${l.vulnerabilities.length} known vulnerabilit${l.vulnerabilities.length === 1 ? 'y' : 'ies'} (${worst}): ${l.vulnerabilities[0].summary || l.vulnerabilities[0].cve?.[0] || 'see details'}. Update to ${latestFix(l)} or newer.`);
  }
  if (libs.libraries.length && !vulnLibs.length) f('ok', `${libs.libraries.length} recognised JavaScript librar${libs.libraries.length === 1 ? 'y' : 'ies'}, none with known vulnerabilities.`);

  result.cms = cms;
  if (cms) {
    if (cms.name === 'WordPress') {
      const v = cms.version ? `WordPress ${cms.version}` : 'WordPress (version hidden)';
      if (cms.status === 'latest') f('ok', `${v} is the current release.`);
      else if (cms.status === 'outdated-patch') f('bad', `${v} is behind the current release ${cms.latest}; minor releases are security releases, update now.`);
      else if (cms.status === 'outdated') f('bad', `${v} is behind the current release ${cms.latest}.`);
      else f('info', `${v}; latest is ${cms.latest || 'unknown'}.`);
      if (cms.advisories?.length) f('bad', `WordPress ${cms.version} has ${cms.advisories.length} published vulnerabilit${cms.advisories.length === 1 ? 'y' : 'ies'}: ${cms.advisories[0].title}${cms.advisories[0].fixedIn ? ` (fixed in ${cms.advisories[0].fixedIn})` : ''}.`);
      const outdated = cms.plugins.filter((p) => p.status === 'outdated');
      const vulnerable = cms.plugins.filter((p) => p.vulnerabilities?.length);
      const unknown = cms.plugins.filter((p) => p.status === 'not-in-directory');
      const confirmedVuln = vulnerable.filter((p) => p.version);
      const unconfirmed = vulnerable.filter((p) => !p.version);
      if (confirmedVuln.length) f('bad', `${confirmedVuln.length} plugin${confirmedVuln.length === 1 ? '' : 's'} with published vulnerabilities for the installed version: ${confirmedVuln.map((p) => `${p.slug} ${p.version} (${p.vulnerabilities[0].title}${p.vulnerabilities[0].fixedIn ? ', fixed in ' + p.vulnerabilities[0].fixedIn : ''})`).join('; ')}.`);
      if (unconfirmed.length) f('warn', `${unconfirmed.length} plugin${unconfirmed.length === 1 ? '' : 's'} with a vulnerability history but no visible version: ${unconfirmed.map((p) => p.slug).join(', ')}. Confirm the installed version from inside.`);
      if (cms.themeVulnerabilities?.length) f('bad', `Theme ${cms.theme} has ${cms.themeVulnerabilities.length} unpatched vulnerabilit${cms.themeVulnerabilities.length === 1 ? 'y' : 'ies'}: ${cms.themeVulnerabilities[0].title}.`);
      if (outdated.length) f('warn', `${outdated.length} of ${cms.plugins.length} visible plugins outdated: ${outdated.slice(0, 5).map((p) => `${p.slug} ${p.version} → ${p.latest}`).join(', ')}${outdated.length > 5 ? ', …' : ''}.`);
      else if (cms.plugins.length) f('ok', `${cms.plugins.length} visible plugin${cms.plugins.length === 1 ? '' : 's'}, all current${unknown.length ? ` (${unknown.length} not in the wordpress.org directory, premium or custom)` : ''}.`);
      if (!cms.vulnFeed) f('info', 'Vulnerability feed not loaded yet; only version freshness is checked.');
    } else {
      const v = cms.version ? `${cms.name} ${cms.version}` : `${cms.name} (version hidden)`;
      if (cms.status === 'eol') f('bad', `${v} is end-of-life; latest is ${cms.latest}.`);
      else if (cms.status === 'latest') f('ok', `${v} is current.`);
      else f('info', `${v}${cms.latest ? `; latest is ${cms.latest}` : ''}.`);
    }
  }

  result.server = server;
  for (const s of server) {
    const v = s.version ? `${s.name} ${s.version}` : s.name;
    if (s.status === 'eol') f('bad', `${v} is end-of-life${s.latest ? ` (current: ${s.latest})` : ''}; it receives no security fixes.`);
    else if (s.status === 'outdated') f('warn', `${v} is behind ${s.latest} on the ${s.cycle} branch.`);
    else if (s.status === 'distro') f('info', `${v} is a distribution build; the distro backports fixes, check the package changelog.`);
    else if (s.status === 'latest') f('ok', `${v} is current on the ${s.cycle} branch.`);
  }
  return result;
}

function latestFix(lib) {
  const fixes = lib.vulnerabilities.map((v) => v.fixedIn).filter(Boolean).sort(cmpVer);
  return fixes.length ? fixes[fixes.length - 1] : 'the latest version';
}
