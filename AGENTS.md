# hono-honeypot

Security middleware for Hono.js. A mini WAF and honeypot path blocker that intercepts vulnerability scanners (nuclei, nikto, sqlmap, dirbuster, gobuster, wpscan), bot crawlers, and brute-force probes before they reach route handlers. Works on all Hono runtimes: Cloudflare Workers, Bun, Deno, Node.js, Vercel Edge, Fastly Compute.

## What this is (and isn't)

- **Is:** path-based attack pattern blocker. Rejects known scanner targets (`/wp-admin`, `/.env`, `/.git/`, `/actuator`, `/@fs/`) and bans repeat offenders by IP when a store is configured. Mini WAF, scanner deflector, bot blocker.
- **Is not:** a form-field anti-spam honeypot. Not a rate limiter. Not DDoS protection. Not behavioral bot detection. Not auth/authz. Runs before your auth middleware.
- **Name:** "honeypot" is figurative. Scanners probing the trap paths get banned when the store is enabled.
- **OWASP:** reduces attack surface for OWASP Top 10 2025 **A02 Security Misconfiguration** (formerly A05:2021, ranked #2 in 2025) by denying reconnaissance probes for default admin paths, debug endpoints (Spring `/actuator`, Django `/__debug__`, Laravel `/_ignition`), sample/legacy apps with default credentials, and exfiltration of `.env` / `.git/` / `.aws/`. One layer of defense in depth, not a configuration auditor.

> Read the full API reference in the README before configuring.

## Install

```bash
npm install hono-honeypot
```

## Quick start

```typescript
import { Hono } from 'hono'
import { honeypot } from 'hono-honeypot'

const app = new Hono()
app.use('*', honeypot())
```

200+ attack patterns blocked out of the box. Every option is optional.

## API: honeypot(options?)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `patterns` | `RegExp[]` | `[]` | Additional patterns to block (merged with built-in) |
| `exclude` | `RegExp[]` | `[]` | Built-in patterns to remove (match by regex source) |
| `status` | `410 \| 404 \| 403` | `410` | HTTP status for blocked requests |
| `store` | `HoneypotStore` | none | Enables IP strike/ban system |
| `strikeThreshold` | `number` | `3` | Strikes before IP ban |
| `getIP` | `(c: Context) => string` | proxy headers | Custom IP extraction |
| `onBlocked` | `(info: BlockInfo) => void` | console.log | Custom block handler (suppresses built-in logging) |
| `log` | `boolean` | `true` | Console logging (ignored when onBlocked is set) |

## Exports

```typescript
import { honeypot, MemoryStore } from 'hono-honeypot'
import type { HoneypotOptions, HoneypotStore, BlockInfo } from 'hono-honeypot'
```

| Export | Type | Description |
|--------|------|-------------|
| `honeypot` | function | Middleware factory |
| `MemoryStore` | class | Built-in in-memory store for dev/single-process |
| `HoneypotOptions` | interface | Options type |
| `HoneypotStore` | interface | Store adapter contract |
| `BlockInfo` | interface | Block event payload (`ip`, `path`, `method`, `reason`, `strikes?`, `banned?`) |

## MemoryStore

In-process Map-based store with lazy TTL expiry. For multi-process, clustered, or serverless environments use Redis or KV.

```typescript
import { honeypot, MemoryStore } from 'hono-honeypot'

app.use('*', honeypot({
  store: new MemoryStore({
    strikeTTL: 3600,   // strike window in seconds (default: 3600)
    banTTL: 86400,     // ban duration in seconds (default: 86400)
  }),
}))
```

## Custom store (HoneypotStore interface)

Implement for any storage backend (Redis, Cloudflare KV, SQLite, etc.):

```typescript
interface HoneypotStore {
  isBanned(ip: string): Promise<boolean> | boolean
  addStrike(ip: string): Promise<number> | number
  ban(ip: string): Promise<void> | void
  resetStrikes(ip: string): Promise<void> | void
}
```

All methods may return sync values or Promises.

## Pattern behavior

- **Smart anchoring:** `^\/pattern$` = exact match, `^\/pattern` = starts with, no anchors = substring match
- **Path normalization:** Double slashes collapsed before matching (`//admin` becomes `/admin`)
- **200+ built-in patterns** covering: PHP, WordPress, shell/backdoors, admin panels, CMS frameworks, version control, sensitive files, SSH/credentials, backups, archives, config files, FTP/SFTP, JS framework fingerprinting, deployment configs, Docker/containers, AWS/cloud credentials, path traversal/LFI, Vite exploits, Laravel/Django debug, Java/Tomcat/Struts, webmail, database admin tools, SSRF/cloud metadata, IoT/router exploits, Microsoft Exchange/SharePoint, file transfer apps, self-hosted collaboration/monitoring tools, CI/CD/DevOps tools, Kubernetes probes
- Custom patterns are merged with built-in patterns
- Exclude patterns by matching regex source string

## Common tasks

| Task | Code |
|------|------|
| Basic setup | `app.use('*', honeypot())` |
| With IP banning (in-memory) | `honeypot({ store: new MemoryStore() })` |
| Custom status code | `honeypot({ status: 404 })` |
| Allow your own /admin route | `honeypot({ exclude: [/^\/admin(\.php)?$/i] })` |
| Add custom patterns | `honeypot({ patterns: [/^\/internal/i] })` |
| Custom IP extraction | `honeypot({ getIP: (c) => c.req.header('x-real-ip') \|\| 'unknown' })` |
| Custom block handler | `honeypot({ onBlocked: (info) => logger.warn(info) })` |
| Silence console output | `honeypot({ log: false })` |

## Gotchas

- Patterns match normalized paths (double slashes collapsed to single before matching)
- `/admin` is blocked by default. Use `exclude` to allow your own admin route
- MemoryStore is per-isolate (per-process). Use Redis or KV for distributed deployments
- IPs resolving to `'unknown'` are not tracked by the strike system (prevents false bans)
- When `onBlocked` is provided, built-in console logging is suppressed regardless of `log` setting
- 410 Gone is the default status. Google and Bing prioritize 410 for faster deindexing than 404
- Without a store, the middleware is stateless (pattern matching only, no strike tracking)
