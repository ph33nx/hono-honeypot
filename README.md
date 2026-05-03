<p align="center">
  <a href="https://github.com/ph33nx/hono-honeypot">
    <img src="https://raw.githubusercontent.com/ph33nx/hono-honeypot/main/assets/hero.png" alt="hono-honeypot. Block bots before they reach your routes. Zero dependencies, MIT licensed." width="100%">
  </a>
</p>

# hono-honeypot

Security middleware for [Hono.js](https://hono.dev). A mini WAF and honeypot path blocker that intercepts vulnerability scanners (nuclei, nikto, sqlmap, dirbuster, gobuster, wpscan), bot crawlers, and brute-force probes before they reach your route handlers.

Built from analyzing hundreds of thousands of real-world malicious requests in production. Pattern matching runs in sub-millisecond time across all Hono runtimes: Cloudflare Workers, Bun, Deno, Node.js, Vercel Edge, and Fastly Compute.

## What this is (and isn't)

`hono-honeypot` is **path-based attack pattern blocking** for Hono.js. It rejects requests to known scanner targets (`/wp-admin`, `/.env`, `/.git/`, `/actuator`, `/@fs/`, etc.) before they reach your handlers, optionally banning repeat offenders by IP. Treat it as a mini web application firewall (WAF), scanner deflector, or bot blocker.

| What it blocks | What it does NOT block |
|---|---|
| Vulnerability scanners: nuclei, nikto, sqlmap, dirbuster, gobuster, wpscan | Spam form submissions (use a hidden form-field trap for that) |
| WordPress, PHP, cPanel, phpMyAdmin probes | Application-level rate limits (use a separate rate limiter) |
| `.env`, `.git`, `.aws`, `.ssh` exfiltration attempts | DDoS and volumetric attacks (terminate at Cloudflare or upstream proxy) |
| Vite dev server exploits (CVE-2025-30208) | OWASP Top 10 injection against your own routes (input validation belongs in handlers) |
| Path traversal probes, SSRF cloud-metadata probes | Behavioral bot detection (use a fingerprint or device-intelligence service) |
| 200+ baked-in patterns covering Spring Actuator, Magento REST, Exchange OWA, IoT routers, K8s probes, CI/CD admin panels, and more | Authentication or authorization (this runs before your auth middleware) |

The name "honeypot" is figurative: when the IP store is enabled, scanners that probe the trap paths get stuck (struck and banned). It is **not** a form-field anti-spam honeypot.

### OWASP alignment

Reduces attack surface for [**OWASP Top 10 2025 A02 Security Misconfiguration**](https://owasp.org/Top10/2025/) (formerly A05:2021, ranked #2 in the 2025 edition). Specifically denies reconnaissance probes targeting:

- **Sample / legacy applications** left on production with default admin accounts (OWASP A02 Scenario #1: WordPress, phpMyAdmin, Adminer, Magento, cPanel)
- **Debug endpoints** insecure by default (Spring `/actuator`, Django `/__debug__`, Laravel `/_ignition`, Vite `/@fs/`)
- **Unnecessary features** enabled in production (admin panels, dev-tooling routes, IoT vendor backdoors)
- **Sensitive files** that should never be web-accessible (`.env`, `.git/`, `.aws/`, `.ssh/`, backup files, dependency manifests)

This is one layer of defense in depth, not a configuration auditor. Pair with proper hardening, secret management, and removal of unused frameworks.

## Install

```bash
npm install hono-honeypot
```

## Quick Start

```typescript
import { Hono } from 'hono'
import { honeypot } from 'hono-honeypot'

const app = new Hono()
app.use('*', honeypot())
```

That's it. 200+ attack patterns are blocked out of the box. Every option below is **optional**.

---

## API Reference

### `honeypot(options?)`

Returns Hono middleware. All options are optional.

```typescript
app.use('*', honeypot({
  patterns,          // RegExp[]           — additional patterns to block
  exclude,           // RegExp[]           — built-in patterns to remove
  status,            // 410 | 404 | 403    — response status (default: 410)
  store,             // HoneypotStore      — enables IP strike/ban system
  strikeThreshold,   // number             — strikes before ban (default: 3)
  getIP,             // (c: Context) => string — custom IP extraction
  onBlocked,         // (info: BlockInfo) => void — custom block handler
  log,               // boolean            — console logging (default: true)
}))
```

---

## Features

### Pattern Matching (stateless, zero-config)

<p align="center">
  <img src="https://raw.githubusercontent.com/ph33nx/hono-honeypot/main/assets/patterns.png" alt="200+ attack patterns built in. wp-admin, .env, .git, /actuator, /@fs/. Smart anchoring, no false positives." width="100%">
</p>

Out of the box, the middleware matches request paths against 200+ regex patterns covering:

| Category | Examples |
|----------|----------|
| PHP/WordPress | `*.php`, `/wp-admin`, `/xmlrpc.php`, `/wp-content/` |
| Admin panels | `/admin`, `/phpmyadmin`, `/cpanel`, `/cgi-bin` |
| CMS frameworks | `/typo3`, `/joomla`, `/drupal`, `/magento` |
| Magento REST API | `/rest/V1/store/storeConfigs` and store-scope variants |
| JS framework fingerprinting | `/_next`, `/_rsc`, `/_vercel`, `next.config.js`, `nuxt.config.ts` |
| Deployment configs | `serverless.yml`, `vercel.json`, `netlify.toml`, `package.json` |
| Docker/container | `docker-compose.yml`, `Dockerfile`, `/docker/` |
| AWS/cloud credentials | `/aws/*`, `aws_s3`, `aws_ses`, `/.aws/` |
| Version control | `/.git/`, `/.svn/`, `/.hg/` |
| Sensitive files | `/.env`, `/.htaccess`, `/.htpasswd`, `*.sql` |
| SSH/auth tokens | `/.ssh/`, `/id_rsa`, `/.npmrc`, `/.pypirc` |
| System path traversal | `/var/task/`, `/var/log/`, `/opt/` |
| Command injection | `$(pwd)`, backtick injection |
| URL normalisation probes | Zero-width Unicode (`U+200B`, `U+FEFF` BOM, U+200C–U+200F, U+202A–U+202E directional overrides) |
| Log files | `*.log`, `error_log` |
| Java/Spring Boot | `/WEB-INF`, `/manager/html`, `/solr`, `/actuator` |
| Dependency manifests | `composer.json`, `Gemfile`, `requirements.txt` |
| WYSIWYG editors | `/ckeditor`, `/tinymce`, `/elfinder` |
| OS metadata | `.DS_Store`, `Thumbs.db` |
| Backup files | `*.bak`, `*.old`, `*.backup`, `*.swp` |
| Path traversal / LFI | `../`, `..%2f`, `/etc/passwd`, `/proc/self/environ` |
| Vite dev server exploits | `/@fs/`, `/@vite/`, `/@id/` (CVE-2025-30208) |
| Laravel/Django debug | `/_ignition`, `/__debug__` |
| SSRF / cloud metadata | `/proxy/`, `169.254.169.254`, `/latest/meta-data` |
| IoT / router exploits | `/HNAP1/`, `/boaform/`, `/GponForm/`, `/setup.cgi` |
| Microsoft Exchange/SharePoint | `/owa/`, `/aspnet_client/`, `/ecp/`, `/_layouts/`, `/_vti_bin/` |
| Self-hosted apps | `/nextcloud/`, `/owncloud/`, `/WebInterface/` (CrushFTP) |
| Collaboration/monitoring | `/geoserver/`, `/confluence/`, `/jira/`, `/grafana/`, `/kibana/`, `/prometheus/` |
| CI/CD / DevOps | `/jenkins/`, `/portainer/`, `/gitea/`, `/gitlab/` |
| Database admin aliases | `/adminer`, `/pma/`, `/myadmin/`, `/mysqladmin`, `/dbadmin` |
| Webmail | `/roundcube/`, `/webmail/` |
| Kubernetes / container | `/metrics`, `/healthz`, `/readyz`, `/livez`, `/.dockerenv` |
| Brute force discovery | `/old`, `/test`, `/demo`, `/script`, `/2017`, `/2024` |

Patterns use smart anchoring to prevent false positives:

```
/admin     → blocked (exact root match)
/api/admin → allowed (nested path, not root)
/login     → allowed (legitimate app route)
/blog      → allowed (legitimate app route)
```

### Custom Patterns

Add application-specific patterns. Merged with the built-in set.

```typescript
app.use('*', honeypot({
  patterns: [
    /^\/internal-api/i,
    /^\/debug/i,
  ],
}))
```

### Excluding Built-in Patterns

Remove specific built-in patterns by matching their regex source string.

```typescript
app.use('*', honeypot({
  exclude: [
    /^\/admin(\.php)?$/i,  // Allow your own /admin route
  ],
}))
```

### Response Status

Default is `410 Gone`. Alternatives: `404`, `403`.

```typescript
app.use('*', honeypot({ status: 404 }))
```

Why `410 Gone` is the default:
- Google and Bing prioritize `410` for faster deindexing over `404`
- Scanners with retry logic treat `410` as permanent and stop faster than `404`
- Empty response body minimizes bandwidth under high-volume probing

---

## IP Strike/Ban System

<p align="center">
  <img src="https://raw.githubusercontent.com/ph33nx/hono-honeypot/main/assets/strike-ban.png" alt="3 strikes, 24-hour ban. Memory, Redis, or Cloudflare KV. O(1) ban check before pattern matching." width="100%">
</p>

Without a store, the middleware is stateless: it blocks matching paths but imposes no penalty on repeat offenders. With a store, it tracks strikes per IP and bans IPs that exceed the threshold.

**Flow:**
1. Request matches attack pattern → strike recorded against IP
2. IP reaches `strikeThreshold` (default: 3) → IP is banned
3. Banned IP sends any request → instant `410` response, no pattern matching needed (O(1) lookup)

### MemoryStore (built-in)

In-process Map-based store with lazy TTL expiry. Suitable for single-process deployments and development.

```typescript
import { honeypot, MemoryStore } from 'hono-honeypot'

app.use('*', honeypot({
  store: new MemoryStore({
    strikeTTL: 3600,    // optional — strike window in seconds (default: 3600 / 1 hour)
    banTTL: 86400,      // optional — ban duration in seconds (default: 86400 / 24 hours)
  }),
  strikeThreshold: 3,   // optional — default: 3
}))
```

> **Note:** MemoryStore state is per-isolate. In multi-process, clustered, or serverless environments, use a shared store (Redis, KV, etc.).

### Custom Store (Redis, KV, etc.)

Implement the `HoneypotStore` interface to use any storage backend. All methods may return sync values or Promises.

```typescript
interface HoneypotStore {
  /** Check if IP is banned. Called before pattern matching (fast path). */
  isBanned(ip: string): Promise<boolean> | boolean

  /** Record a strike. Return new total count. */
  addStrike(ip: string): Promise<number> | number

  /** Ban an IP. Called when strikes >= threshold. */
  ban(ip: string): Promise<void> | void

  /** Clear strikes. Called after ban is set. */
  resetStrikes(ip: string): Promise<void> | void
}
```

#### Redis example (ioredis)

```typescript
import type { HoneypotStore } from 'hono-honeypot'
import Redis from 'ioredis'

const redis = new Redis()

const redisStore: HoneypotStore = {
  async isBanned(ip) {
    return (await redis.exists(`honeypot:ban:${ip}`)) === 1
  },
  async addStrike(ip) {
    const key = `honeypot:strikes:${ip}`
    const count = await redis.incr(key)
    if (count === 1) await redis.expire(key, 3600)
    return count
  },
  async ban(ip) {
    await redis.setex(`honeypot:ban:${ip}`, 86400, '1')
  },
  async resetStrikes(ip) {
    await redis.del(`honeypot:strikes:${ip}`)
  },
}

app.use('*', honeypot({ store: redisStore }))
```

#### Cloudflare KV example

```typescript
import type { HoneypotStore } from 'hono-honeypot'

function createKVStore(kv: KVNamespace): HoneypotStore {
  return {
    async isBanned(ip) {
      return (await kv.get(`honeypot:ban:${ip}`)) !== null
    },
    async addStrike(ip) {
      const key = `honeypot:strikes:${ip}`
      const current = parseInt((await kv.get(key)) || '0')
      const count = current + 1
      await kv.put(key, String(count), { expirationTtl: 3600 })
      return count
    },
    async ban(ip) {
      await kv.put(`honeypot:ban:${ip}`, '1', { expirationTtl: 86400 })
    },
    async resetStrikes(ip) {
      await kv.delete(`honeypot:strikes:${ip}`)
    },
  }
}

app.use('*', honeypot({ store: createKVStore(env.KV) }))
```

---

## IP Extraction

Default extraction chain: `cf-connecting-ip` > `x-forwarded-for` (first entry) > `x-real-ip` > `'unknown'`.

IPs resolving to `'unknown'` or empty string are not tracked by the strike system (prevents false bans when IP cannot be determined).

Override with a custom function:

```typescript
app.use('*', honeypot({
  getIP: (c) => c.req.header('x-real-ip') || 'unknown',
}))
```

---

## Block Handler (`onBlocked`)

Custom callback fired on every blocked request. When provided, suppresses built-in console logging.

```typescript
app.use('*', honeypot({
  onBlocked: (info) => {
    // info.ip       — client IP
    // info.path     — normalized request path
    // info.method   — HTTP method
    // info.reason   — 'pattern' | 'banned'
    // info.strikes  — current strike count (when store is active, pattern matches only)
    // info.banned   — true if this request triggered a new ban

    logger.warn(`honeypot: ${info.reason} ${info.ip} ${info.method} ${info.path}`)

    if (info.banned) {
      metrics.increment('honeypot.bans')
    }
  },
}))
```

Without `onBlocked`, the middleware logs to console when `log: true` (default):

```
🍯 Blocked [203.0.113.5] GET /wp-admin
🚫 Banned [203.0.113.5] GET /.env BANNED
```

Set `log: false` to suppress all output:

```typescript
app.use('*', honeypot({ log: false }))
```

---

## Exports

```typescript
import { honeypot, MemoryStore } from 'hono-honeypot'
import type { HoneypotOptions, HoneypotStore, BlockInfo } from 'hono-honeypot'
```

| Export | Type | Description |
|--------|------|-------------|
| `honeypot` | function | Middleware factory |
| `MemoryStore` | class | Built-in in-memory store |
| `HoneypotOptions` | interface | Options type |
| `HoneypotStore` | interface | Store adapter contract |
| `BlockInfo` | interface | Block event payload |

---

## Performance

| Metric | Value |
|--------|-------|
| Pattern matching overhead | <1ms per request |
| Ban check (store) | O(1) lookup, runs before pattern matching |
| Memory footprint | ~10KB (pattern array) |
| Bundle size | Zero dependencies beyond `hono` peer dep |

---

## Runtime Compatibility

Tested on all Hono.js runtimes: Cloudflare Workers, Bun, Deno, Node.js (>=18), Vercel Edge Functions, Fastly Compute.

## AI Agents

This package ships `AGENTS.md` in the published npm bundle. AI coding agents (Claude Code, Cursor, GitHub Copilot, OpenAI Codex, Gemini CLI) that support `AGENTS.md` will read it automatically from `node_modules/hono-honeypot/AGENTS.md`.

---

## Contributing

Issues and PRs welcome at [github.com/ph33nx/hono-honeypot](https://github.com/ph33nx/hono-honeypot)

## License

MIT
