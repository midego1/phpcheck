/**
 * Wordfence Intelligence vulnerability feed (v3, scanner variant).
 *
 * refreshFeed(env): downloads the feed once (cron, daily), compacts it to an index keyed by
 * software type + slug, and stores it in KV in a few buckets so each value stays under KV's
 * 25 MB limit. lookup(): reads the bucket a slug belongs to, memoised per isolate.
 *
 * Feed terms: https://www.wordfence.com/wti-community-edition-terms-and-conditions/
 * Each vulnerability keeps a reference URL so results can link back to the record.
 */

import { cmpVer } from './security.js';

const FEED_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner';
const UA = 'php-version-check/0.1 (+https://phpcheck.midego.net)';
const BUCKETS = ['core', 'a-c', 'd-f', 'g-l', 'm-p', 'q-s', 't-z', 'other'];

export function bucketFor(type, slug) {
  if (type === 'core') return 'core';
  const c = (slug || '')[0] || '';
  if (c >= 'a' && c <= 'c') return 'a-c';
  if (c >= 'd' && c <= 'f') return 'd-f';
  if (c >= 'g' && c <= 'l') return 'g-l';
  if (c >= 'm' && c <= 'p') return 'm-p';
  if (c >= 'q' && c <= 's') return 'q-s';
  if (c >= 't' && c <= 'z') return 't-z';
  return 'other';
}

// Compact one feed record's software entry into what matching and display need.
function compact(rec, sw) {
  const ranges = Object.values(sw.affected_versions || {}).map((r) => ({
    from: r.from_version === '*' ? null : r.from_version,
    fromInc: r.from_inclusive !== false,
    to: r.to_version === '*' ? null : r.to_version,
    toInc: r.to_inclusive !== false,
  }));
  return {
    id: rec.id,
    title: rec.title,
    ranges,
    patched: !!sw.patched,
    patchedVersions: (sw.patched_versions || []).slice(0, 5),
    informational: !!rec.informational,
    published: rec.published ? String(rec.published).slice(0, 10) : null,
    ref: (rec.references || []).find((u) => /wordfence\.com\/threat-intel/.test(u)) || (rec.references || [])[0] || null,
    cve: rec.cve || null,
    cvss: rec.cvss?.score ?? null,
    rating: rec.cvss?.rating || null,
  };
}

export async function refreshFeed(env) {
  if (!env.WORDFENCE_KEY) return { ok: false, error: 'WORDFENCE_KEY secret not set' };
  if (!env.VULN_DB) return { ok: false, error: 'VULN_DB KV binding missing' };
  const res = await fetch(FEED_URL, { headers: { authorization: `Bearer ${env.WORDFENCE_KEY}`, 'user-agent': UA, accept: 'application/json' }, signal: AbortSignal.timeout(120000) });
  if (!res.ok) return { ok: false, error: `feed returned HTTP ${res.status}` };
  const feed = await res.json();
  const buckets = Object.fromEntries(BUCKETS.map((b) => [b, {}]));
  let records = 0;
  for (const rec of Object.values(feed)) {
    if (!rec || !Array.isArray(rec.software)) continue;
    for (const sw of rec.software) {
      const type = sw.type === 'core' ? 'core' : sw.type === 'theme' ? 'theme' : 'plugin';
      const slug = type === 'core' ? 'wordpress' : String(sw.slug || '').toLowerCase();
      if (!slug) continue;
      const key = `${type}:${slug}`;
      const b = buckets[bucketFor(type, slug)];
      (b[key] = b[key] || []).push(compact(rec, sw));
      records++;
    }
  }
  const meta = { updatedAt: new Date().toISOString(), vulnerabilities: Object.keys(feed).length, entries: records, sizes: {} };
  for (const b of BUCKETS) {
    const json = JSON.stringify(buckets[b]);
    meta.sizes[b] = json.length;
    await env.VULN_DB.put(`wf:${b}`, json);
  }
  await env.VULN_DB.put('wf:meta', JSON.stringify(meta));
  return { ok: true, ...meta };
}

const memo = new Map(); // bucket -> { at, data }

async function bucket(env, name) {
  if (!env.VULN_DB) return null;
  const m = memo.get(name);
  if (m && Date.now() - m.at < 30 * 60 * 1000) return m.data;
  const data = await env.VULN_DB.get(`wf:${name}`, { type: 'json' }).catch(() => null);
  memo.set(name, { at: Date.now(), data });
  return data;
}

export async function feedMeta(env) {
  if (!env.VULN_DB) return null;
  const m = memo.get('meta');
  if (m && Date.now() - m.at < 10 * 60 * 1000) return m.data;
  const data = await env.VULN_DB.get('wf:meta', { type: 'json' }).catch(() => null);
  memo.set('meta', { at: Date.now(), data });
  return data;
}

function affected(version, r) {
  if (!version) return true; // unknown version: report everything, caller marks it as unconfirmed
  if (r.from && (r.fromInc ? cmpVer(version, r.from) < 0 : cmpVer(version, r.from) <= 0)) return false;
  if (r.to && (r.toInc ? cmpVer(version, r.to) > 0 : cmpVer(version, r.to) >= 0)) return false;
  return true;
}

/** Vulnerabilities that apply to `version` of the given software. version may be null (unknown). */
export async function lookup(env, type, slug, version) {
  const b = await bucket(env, bucketFor(type, slug));
  if (!b) return null; // feed not loaded
  const list = b[`${type}:${type === 'core' ? 'wordpress' : slug}`] || [];
  const hits = list.filter((v) => !v.informational && v.ranges.some((r) => affected(version, r)));
  return hits
    .sort((a, b2) => (b2.cvss ?? 0) - (a.cvss ?? 0) || String(b2.published).localeCompare(String(a.published)))
    .slice(0, 10)
    .map((v) => ({ title: v.title, cve: v.cve, cvss: v.cvss, rating: v.rating, patched: v.patched, fixedIn: v.patchedVersions[0] || null, published: v.published, ref: v.ref, confirmed: !!version }));
}
