# hono-honeypot

> Production-grade security middleware for Hono.js - ultrafast edge protection against malicious traffic

Battle-tested honeypot middleware engineered specifically for the Hono.js framework. Built after analyzing hundreds of thousands of real-world bot requests across production systems, this middleware identifies and blocks automated attacks, vulnerability scanners, and malicious crawlers before they reach your application logic.

Designed for Hono's ultrafast edge runtime architecture, delivering sub-millisecond pattern matching on Cloudflare Workers, Bun, Deno, and modern JavaScript runtimes. Returns `410 Gone` responses to permanently deter bots and accelerate search engine deindexing of non-existent resources.

## Features

- ✅ **Zero dependencies** - Pure TypeScript pattern matching, no external libraries or runtime requirements
- ⚡ **<1ms execution** - Early termination firewall logic with minimal CPU overhead, optimized for edge computing
- 🛡️ **Production-ready** - Blocks 100+ attack vectors discovered from real production bot traffic analysis
- 🌍 **Universal edge support** - Native compatibility with Cloudflare Workers, Bun, Deno, Vercel Edge, Node.js
- 🔧 **Customizable** - Add custom patterns or exclude built-in rules for your specific use case
- 🚀 **SEO-friendly** - Uses 410 Gone status for faster Google/Bing deindexing and reduced server load

## Installation

```bash
npm install hono-honeypot
# or
pnpm add hono-honeypot
# or
bun add hono-honeypot
```

## Usage

### Basic Setup

```typescript
import { Hono } from 'hono'
import { honeypot } from 'hono-honeypot'

const app = new Hono()

// Apply globally (recommended - place early in middleware chain)
app.use('*', honeypot())

app.get('/', (c) => c.text('Hello!'))

export default app
```

### With Options

```typescript
import { honeypot } from 'hono-honeypot'

app.use('*', honeypot({
  // Add custom attack patterns to block
  patterns: [
    /^\/custom-admin/i,
    /^\/secret/i,
  ],

  // Exclude built-in patterns (e.g., allow /admin for your own routes)
  exclude: [
    /^\/admin$/i, // Allow /admin but still block other admin patterns
  ],

  // Enable request logging (default: true)
  log: true,

  // HTTP status code (default: 410 Gone for faster bot deterrence)
  status: 410, // or 403 Forbidden, 404 Not Found
}))
```

### Protect Specific Routes

```typescript
// Only protect API routes
app.use('/api/*', honeypot())

// Exclude certain paths
app.use('*', async (c, next) => {
  if (c.req.path.startsWith('/public')) {
    return next()
  }
  return honeypot()(c, next)
})
```

## What It Blocks

Intercepts 100+ attack vectors discovered from real production traffic including:

- **PHP vulnerability scanners**: `*.php`, `/phpinfo`, `/config.php`, `/eval-stdin.php`
- **WordPress brute force**: `/wp-admin`, `/wp-login.php`, `/xmlrpc.php`, `/wp-config.php`
- **Admin panel enumeration**: `/admin`, `/phpmyadmin`, `/cpanel`, `/cgi-bin`
- **CMS framework exploits**: `/typo3`, `/joomla`, `/drupal`, `/magento`
- **Sensitive file probing**: `/.env`, `/.git`, `*.sql`, `/node_modules`, `/database.yml`
- **Backup file discovery**: `/backup`, `/old`, `/test`, `/demo`, `/temp`
- **Auth endpoint scanning**: `/login`, `/register`, `/dashboard` (exact matches only)
- **Directory brute force**: `/2017`, `/2018`, etc. (year-based folder guessing)
- **Web shell detection**: `/shell.php`, `/c99.php`, `/r57.php`

**Smart anchoring prevents false positives:**
- ✅ Blocks `/admin` but allows `/api/admin`
- ✅ Blocks `/blog` but allows `/blogs`
- ✅ Blocks `/login` but allows `/api/auth/login`

## Why 410 Gone?

Returns `410 Gone` (not `404 Not Found`) for better bot deterrence and SEO hygiene:

- **Search engine optimization**: Google and Bing prioritize `410` responses for permanent removal from search indexes
- **Bot mitigation**: Web scrapers and vulnerability scanners stop retrying sooner, reducing server load
- **Bandwidth savings**: Empty response body conserves bandwidth during high-volume DDoS-style attacks
- **Security best practice**: Signals permanent unavailability, not temporary 404 errors that encourage retry logic

## Configuration

### Options API

```typescript
interface HoneypotOptions {
  /**
   * Add custom attack patterns to block (e.g., /internal, /private)
   * Merged with built-in 100+ patterns
   */
  patterns?: RegExp[]

  /**
   * Exclude specific built-in patterns (e.g., allow /admin for your own routes)
   * Useful when you need legitimate routes that match attack patterns
   */
  exclude?: RegExp[]

  /**
   * Log blocked requests to console with 🍯 emoji and IP address
   * @default true
   */
  log?: boolean

  /**
   * HTTP status code to return for blocked requests
   * @default 410 - 410 Gone (fastest bot deterrence + search engine deindexing)
   *          404 - Not Found (standard but encourages bot retries)
   *          403 - Forbidden (signals authentication issue, may trigger escalation)
   */
  status?: 410 | 404 | 403
}
```

### Logging Output

```bash
🍯 Blocked [192.168.1.1] GET /wp-admin
🍯 Blocked [203.0.113.5] POST /phpmyadmin
🍯 Blocked [198.51.100.42] HEAD /backup
```

## Performance

- **Overhead**: <1ms per request
- **Memory**: ~8KB (pattern array)
- **CPU**: Minimal (regex matching, short-circuits on first match)

## Best Practices

1. **Place early** in middleware chain (before rate limiters, authentication, and business logic)
2. **Use exclude option** if you have legitimate routes matching attack patterns (e.g., `/admin` dashboard)
3. **Test thoroughly** with your application routes to prevent false positives blocking real users
4. **Monitor logs** in staging/production to identify new attack vectors and emerging bot patterns
5. **Add custom patterns** specific to your application architecture (internal endpoints, legacy routes)
6. **Combine with rate limiting** for defense-in-depth security strategy
7. **Review periodically** to update patterns as new vulnerabilities and scanning techniques emerge

## Framework Compatibility

Works with all Hono.js runtimes:

- ✅ Cloudflare Workers
- ✅ Bun
- ✅ Deno
- ✅ Node.js
- ✅ Vercel Edge Functions
- ✅ Fastly Compute

## Migration from Express

```typescript
// Before (Express)
app.use((req, res, next) => {
  if (req.path.includes('wp-admin')) {
    return res.status(410).end()
  }
  next()
})

// After (Hono)
app.use('*', honeypot())
```

## Contributing

Issues and PRs welcome at [github.com/ph33nx/hono-honeypot](https://github.com/ph33nx/hono-honeypot)

## License

MIT © [ph33nx](https://github.com/ph33nx)
