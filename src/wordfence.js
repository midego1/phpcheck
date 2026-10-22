/**
 * WordPress vulnerability lookups against a static index built from the Wordfence Intelligence
 * production feed by scripts/build-vuln-index.mjs (run daily by .github/workflows/vuln-feed.yml)
 * and deployed as assets under /vuln/. The Worker never downloads or parses the feed itself:
 * one lookup reads one small JSON file (all slugs sharing a two-character prefix).
 *
 * Feed terms: https://www.wordfence.com/wti-community-edition-terms-and-conditions/
 * Every vulnerability keeps a link to its Wordfence record.
 */

import { cmpVer } from './security.js';

export function bucketPath(type, slug) {
  if (type === 'core') return '/vuln/core.json';
  const s = String(slug || '').toLowerCase();
  const prefix = (s.slice(0, 2).replace(/[^a-z0-9]/g, '_') || '__').padEnd(2, '_');
  return `/vuln/${type}/${prefix}.json`;
}

const memos = new WeakMap(); // ASSETS binding -> Map(path -> { at, data })

async function readAsset(env, path) {
  if (!env?.ASSETS) return null;
  let memo = memos.get(env.ASSETS);
  if (!memo) { memo = new Map(); memos.set(env.ASSETS, memo); }
  const m = memo.get(path);
  if (m && Date.now() - m.at < 15 * 60 * 1000) return m.data;
  let data = null;
  try {
    const res = await env.ASSETS.fetch(new Request('https://assets.internal' + path));
    if (res.status === 200) data = await res.json();
    else if (res.status === 404) data = {}; // index exists but nothing under this prefix, or no index yet
  } catch {
    data = null;
  }
  memo.set(path, { at: Date.now(), data });
  return data;
}

export async function feedMeta(env) {
  const m = await readAsset(env, '/vuln/meta.json');
  return m && m.updatedAt ? m : null;
}

function affected(version, r) {
  if (!version) return true; // unknown version: report the history, caller marks it unconfirmed
  if (r.from && (r.fromInc ? cmpVer(version, r.from) < 0 : cmpVer(version, r.from) <= 0)) return false;
  if (r.to && (r.toInc ? cmpVer(version, r.to) > 0 : cmpVer(version, r.to) >= 0)) return false;
  return true;
}

/**
 * Vulnerabilities that apply to `version` of the given software (version may be null).
 * Returns null when no index is deployed, so callers can tell "feed missing" from "no findings".
 */
export async function lookup(env, type, slug, version) {
  const meta = await feedMeta(env);
  if (!meta) return null;
  const b = await readAsset(env, bucketPath(type, slug));
  if (!b) return null;
  const list = b[type === 'core' ? 'wordpress' : String(slug).toLowerCase()] || [];
  return list
    .filter((v) => !v.informational && v.ranges.some((r) => affected(version, r)))
    .sort((a, b2) => (b2.cvss ?? 0) - (a.cvss ?? 0) || String(b2.published).localeCompare(String(a.published)))
    .slice(0, 10)
    .map((v) => ({ title: v.title, cve: v.cve, cvss: v.cvss, rating: v.rating, patched: v.patched, fixedIn: v.patchedVersions[0] || null, published: v.published, ref: v.ref, confirmed: !!version }));
}
