#!/usr/bin/env node
/**
 * Build public/vuln/ from the Wordfence Intelligence production feed.
 *
 * Usage: WORDFENCE_KEY=... node scripts/build-vuln-index.mjs [--from file.json] [--out public/vuln]
 *
 * Output: core.json, plugin/<xx>.json, theme/<xx>.json (xx = first two slug characters, non
 * alphanumerics as "_"), meta.json. Each file maps slug -> compact vulnerability list. The whole
 * tree is written to a temporary directory first and swapped in only when every file succeeded,
 * so a failed run never leaves a half-written index.
 */
import { mkdir, writeFile, rm, rename, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

const FEED_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';
const MAX_FILE_BYTES = 20 * 1024 * 1024; // Workers assets allow 25 MiB per file
const args = process.argv.slice(2);
const arg = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const outDir = arg('--out', 'public/vuln');
const fromFile = arg('--from', null);

function prefixOf(slug) {
  const s = String(slug || '').toLowerCase();
  return (s.slice(0, 2).replace(/[^a-z0-9]/g, '_') || '__').padEnd(2, '_');
}

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

async function loadFeed() {
  if (fromFile) return JSON.parse(await readFile(fromFile, 'utf8'));
  const key = process.env.WORDFENCE_KEY;
  if (!key) throw new Error('WORDFENCE_KEY is not set');
  const headers = { authorization: `Bearer ${key}`, 'user-agent': 'php-version-check feed builder (+https://phpcheck.midego.net)', accept: 'application/json' };
  for (let attempt = 1; attempt <= 2; attempt++) {
    const res = await fetch(FEED_URL, { headers });
    if (res.ok) return res.json();
    if (res.status === 429 && attempt === 1) {
      // Wordfence allows roughly one download per 30 minutes per key. Wait as instructed, then retry once.
      const ra = res.headers.get('retry-after');
      let waitSec = ra && /^\d+$/.test(ra) ? Number(ra) : ra ? Math.ceil((Date.parse(ra) - Date.now()) / 1000) : 31 * 60;
      waitSec = Math.min(Math.max(waitSec, 60), 40 * 60);
      console.log(`Wordfence returned 429; waiting ${waitSec}s before retrying once`);
      await new Promise((r) => setTimeout(r, waitSec * 1000));
      continue;
    }
    throw new Error(`Wordfence feed returned HTTP ${res.status}`);
  }
  throw new Error('Wordfence feed still rate limited after waiting');
}

const feed = await loadFeed();
const files = new Map(); // relative path -> { slug -> [vulns] }
let entries = 0;
for (const rec of Object.values(feed)) {
  if (!rec || !Array.isArray(rec.software)) continue;
  for (const sw of rec.software) {
    const type = sw.type === 'core' ? 'core' : sw.type === 'theme' ? 'theme' : 'plugin';
    const slug = type === 'core' ? 'wordpress' : String(sw.slug || '').toLowerCase();
    if (!slug) continue;
    const path = type === 'core' ? 'core.json' : `${type}/${prefixOf(slug)}.json`;
    // Object.create(null): slugs like "constructor" or "__proto__" must not hit Object.prototype.
    const file = files.get(path) || files.set(path, Object.create(null)).get(path);
    (file[slug] = file[slug] || []).push(compact(rec, sw));
    entries++;
  }
}
if (entries < 1000) throw new Error(`Feed looks truncated: only ${entries} software entries`);

const tmp = `${outDir}.tmp-${process.pid}`;
await rm(tmp, { recursive: true, force: true });
await mkdir(join(tmp, 'plugin'), { recursive: true });
await mkdir(join(tmp, 'theme'), { recursive: true });
let largest = 0;
for (const [path, data] of files) {
  const json = JSON.stringify(data);
  const bytes = Buffer.byteLength(json, 'utf8');
  if (bytes > MAX_FILE_BYTES) throw new Error(`${path} is ${bytes} bytes, over the per-file limit`);
  largest = Math.max(largest, bytes);
  await writeFile(join(tmp, path), json);
}
const meta = { updatedAt: new Date().toISOString(), vulnerabilities: Object.keys(feed).length, entries, files: files.size, largestFileBytes: largest, source: 'Wordfence Intelligence production feed' };
await writeFile(join(tmp, 'meta.json'), JSON.stringify(meta));
await rm(outDir, { recursive: true, force: true });
await rename(tmp, outDir);
console.log(JSON.stringify(meta));
