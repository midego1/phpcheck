# PHP Check

Live: https://phpcheck.midego.net · by [@midego1](https://x.com/midego1) · MIT

Cloudflare Worker + one static page. Paste domains, get back which PHP version each site
exposes, whether that is the latest patch for its branch, branch support status, applicable
advisories, every signal that was (and was not) available, and a ready-to-paste agent prompt
for checking, confirming and fixing it on the server.

## Run locally

```bash
npm install
npm run dev        # http://localhost:8787
```

## Deploy

```bash
npx wrangler login
npm run deploy
```

No bindings or secrets needed. Release data comes from php.net and endoflife.date and is
cached 6 h in the Workers Cache API.

## Import from Cloudflare or Vercel

Paste an API token on the page (Cloudflare: `Zone · Zone · Read`; Vercel: account token, optional
team slug/ID) and every domain in the account is added to the list. The token is sent once to the
Worker for the listing requests and is not stored or logged.

## Rate limits

Per client IP, via Workers Rate Limiting bindings (`[[ratelimits]]` in `wrangler.toml`):
30 check requests, 10 imports and 60 MCP calls per minute. HTTP 429 with `Retry-After: 60`.

## API

```
POST /api/import   {"provider":"cloudflare"|"vercel","token":"…","teamId":"optional"}
GET  /api/releases                 current branches, latest patch, support dates
GET  /api/check?target=example.com single check (repeat ?target= for several)
POST /api/check {"targets":[...]}  bulk, max 20 per request; the UI chunks up to 100
```

## How detection works and its limits

Passive only: one HEAD and, when needed, one GET of the homepage with an identifying
User-Agent. The version comes from `X-Powered-By`, `Server` or `X-Php-Version`. Most hosts
disable it (`expose_php = Off`), so expect many "php, no version" and "no signal" results.
PHP presence without a version is inferred from PHPSESSID cookies, CMS/framework headers,
generator meta tags, WordPress asset paths and links to .php files.

Distribution builds (Debian/Ubuntu/RHEL, e.g. `PHP/8.3.6-0ubuntu0.24.04.5`) get their own
verdict because those distros backport security fixes without changing the version number.

Private and local hosts are refused. Nothing is crawled or probed.

## Files

- `src/index.js`   worker: fetch chain, signal extraction, evaluation, agent prompt builder
- `public/index.html` UI: bulk input, filters, details, CSV/JSON export, generic prompts
- `wrangler.toml`

## MCP

Streamable HTTP endpoint at `/mcp` (stateless; JSON responses, no SSE). Tools:
`check_php_version {targets: string[]}` and `php_releases {}`.

```bash
claude mcp add --transport http phpcheck https://phpcheck.midego.net/mcp
```
