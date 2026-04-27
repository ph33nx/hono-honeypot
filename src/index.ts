/**
 * hono-honeypot - Zero-dependency security middleware for Hono.js
 * Blocks bot attacks, vulnerability scanners, and brute-force attempts.
 * Optional store-backed IP banning (3 strikes = 24hr ban by default).
 *
 * @license MIT
 * @author ph33nx <https://github.com/ph33nx>
 */

import type { Context } from 'hono';
import { createMiddleware } from 'hono/factory';

// ─── Types ──────────────────────────────────────────────────────────────

/**
 * Pluggable storage adapter for IP strike tracking and banning.
 * Implement this interface for your storage backend (Redis, KV, SQLite, etc.)
 *
 * All methods may return a value or a Promise — the middleware awaits uniformly.
 *
 * @example Redis adapter
 * ```ts
 * const store: HoneypotStore = {
 *   async isBanned(ip) {
 *     return await redis.exists(`honeypot:ban:${ip}`) === 1;
 *   },
 *   async addStrike(ip) {
 *     const key = `honeypot:strikes:${ip}`;
 *     const count = await redis.incr(key);
 *     if (count === 1) await redis.expire(key, 3600);
 *     return count;
 *   },
 *   async ban(ip) {
 *     await redis.setex(`honeypot:ban:${ip}`, 86400, '1');
 *   },
 *   async resetStrikes(ip) {
 *     await redis.del(`honeypot:strikes:${ip}`);
 *   }
 * };
 * ```
 */
export interface HoneypotStore {
	/** Check if an IP is currently banned. Called BEFORE pattern matching (fast path). */
	isBanned(ip: string): Promise<boolean> | boolean;

	/** Record a strike against an IP. Return the new total count. Called on pattern match. */
	addStrike(ip: string): Promise<number> | number;

	/** Ban an IP. Called when strikes reach the threshold. */
	ban(ip: string): Promise<void> | void;

	/** Clear strikes for an IP. Called after a ban is set. */
	resetStrikes(ip: string): Promise<void> | void;
}

/**
 * Information about a blocked request, passed to the onBlocked callback
 */
export interface BlockInfo {
	/** Client IP address */
	ip: string;
	/** Normalized request path */
	path: string;
	/** HTTP method (GET, POST, etc.) */
	method: string;
	/** Why the request was blocked: pattern match or IP ban */
	reason: 'pattern' | 'banned';
	/** Current strike count (only present for pattern matches when store is active) */
	strikes?: number;
	/** Whether this strike triggered a new ban */
	banned?: boolean;
}

/**
 * Configuration options for honeypot middleware
 */
export interface HoneypotOptions {
	/**
	 * Add custom attack patterns to block (merged with built-in patterns)
	 *
	 * @example
	 * ```ts
	 * patterns: [
	 *   /^\/custom-admin/i,  // Block /custom-admin
	 *   /^\/internal/i,      // Block /internal
	 * ]
	 * ```
	 */
	patterns?: RegExp[];

	/**
	 * Exclude specific built-in patterns (useful for allowing legitimate routes)
	 *
	 * @example
	 * ```ts
	 * // Allow your own /admin dashboard but keep other admin patterns blocked
	 * exclude: [/^\/admin$/i]
	 * ```
	 */
	exclude?: RegExp[];

	/**
	 * Log blocked requests to console with emoji and client IP
	 *
	 * @default true
	 *
	 * When onBlocked is provided, built-in logging is suppressed regardless of this setting.
	 *
	 * @example
	 * Output: `Blocked [192.168.1.1] GET /wp-admin`
	 */
	log?: boolean;

	/**
	 * HTTP status code to return for blocked requests
	 *
	 * @default 410 Gone (fastest bot deterrence + search engine deindexing)
	 *
	 * - **410 Gone**: Signals permanent removal, bots stop retrying faster, Google/Bing prioritize for index removal
	 * - **404 Not Found**: Standard response but encourages bot retry logic
	 * - **403 Forbidden**: May trigger escalation attempts by sophisticated scanners
	 */
	status?: 410 | 404 | 403;

	/**
	 * Pluggable store for IP strike tracking and banning.
	 * When provided, enables the strike/ban system.
	 * Without a store, the middleware is stateless (pattern match only).
	 *
	 * @example
	 * ```ts
	 * import { honeypot, MemoryStore } from 'hono-honeypot'
	 * app.use('*', honeypot({ store: new MemoryStore() }))
	 * ```
	 */
	store?: HoneypotStore;

	/**
	 * Number of pattern-match strikes before an IP is banned.
	 * Banned IPs get blocked on ALL paths (fast path, no pattern matching needed).
	 * @default 3
	 */
	strikeThreshold?: number;

	/**
	 * Extract client IP from the request context.
	 * Default checks: cf-connecting-ip > x-forwarded-for > x-real-ip > 'unknown'
	 * IPs resolving to 'unknown' are not tracked (prevents false bans).
	 *
	 * @example
	 * ```ts
	 * // Use Hono's built-in IP resolution
	 * getIP: (c) => c.req.header('x-real-ip') || 'unknown'
	 * ```
	 */
	getIP?: (c: Context) => string;

	/**
	 * Called when a request is blocked (pattern match or ban).
	 * Use for custom logging, webhooks, metrics, etc.
	 * When provided, built-in console.log is suppressed.
	 *
	 * @example
	 * ```ts
	 * onBlocked: (info) => {
	 *   console.log(`[honeypot] ${info.reason}: ${info.ip} ${info.method} ${info.path}`);
	 *   if (info.banned) analytics.track('ip_banned', { ip: info.ip });
	 * }
	 * ```
	 */
	onBlocked?: (info: BlockInfo) => void | Promise<void>;
}

// ─── MemoryStore ────────────────────────────────────────────────────────

/**
 * In-memory store for development and single-process deployments.
 * Uses lazy expiry (checks on read, no timers).
 *
 * NOT suitable for multi-process, clustered, or serverless environments
 * where each isolate has its own memory. Use a Redis or KV-backed store
 * for production distributed deployments.
 *
 * @example
 * ```ts
 * import { honeypot, MemoryStore } from 'hono-honeypot'
 *
 * app.use('*', honeypot({
 *   store: new MemoryStore({ strikeTTL: 3600, banTTL: 86400 })
 * }))
 * ```
 */
export class MemoryStore implements HoneypotStore {
	private strikes = new Map<string, { count: number; expires: number }>();
	private bans = new Map<string, number>();

	private strikeTTL: number;
	private banTTL: number;

	constructor(options?: {
		/** Strike window in seconds. Strikes reset if no new attacks within this period. @default 3600 (1 hour) */
		strikeTTL?: number;
		/** Ban duration in seconds. @default 86400 (24 hours) */
		banTTL?: number;
	}) {
		this.strikeTTL = (options?.strikeTTL ?? 3600) * 1000;
		this.banTTL = (options?.banTTL ?? 86400) * 1000;
	}

	isBanned(ip: string): boolean {
		const expiry = this.bans.get(ip);
		if (expiry === undefined) return false;
		if (Date.now() > expiry) {
			this.bans.delete(ip);
			return false;
		}
		return true;
	}

	addStrike(ip: string): number {
		const now = Date.now();
		const existing = this.strikes.get(ip);

		if (existing && now < existing.expires) {
			existing.count++;
			return existing.count;
		}

		this.strikes.set(ip, { count: 1, expires: now + this.strikeTTL });
		return 1;
	}

	ban(ip: string): void {
		this.bans.set(ip, Date.now() + this.banTTL);
	}

	resetStrikes(ip: string): void {
		this.strikes.delete(ip);
	}
}

// ─── Attack Patterns ────────────────────────────────────────────────────

/**
 * Attack patterns to intercept
 *
 * Pattern rules:
 * - ^pattern$ = exact match (e.g., ^\/admin$ matches /admin, not /api/admin)
 * - ^pattern = starts with (e.g., ^\/wp- matches /wp-admin, not /api/wp-admin)
 * - pattern = substring match (use carefully to avoid false positives)
 *
 * Paths are normalized (double slashes collapsed) before matching
 */
const ATTACK_PATTERNS = [
  // ─── PHP vulnerability scanners ───────────────────────────────────────
  /\.php/i,
  /\/config\.php/i,
  /\/phpinfo/i,
  /\/eval-stdin\.php/i,
  /\/xmlrpc\.php/i,

  // ─── Shell/backdoor patterns (anywhere in path) ──────────────────────
  /\/ALFA_DATA/i,
  /\/c99\.php/i,
  /\/r57\.php/i,
  /\/shell\.php/i,
  /\/webshell/i,

  // ─── WordPress (anchored to root to avoid /api/wordpress-integration) ─
  /^\/wp$/i,
  /^\/wp-/i,
  /^\/wordpress/i,

  // ─── WordPress internals (anywhere in path, always attack probes) ────
  /\/wp-includes\//i,
  /\/wp-content\//i,
  /\/wp-admin/i,
  /wlwmanifest\.xml$/i,

  // ─── Generic upload/file directories (root level) ────────────────────
  /^\/uploads?$/i,
  /^\/images$/i,
  /^\/assets$/i,
  /^\/files$/i,
  /^\/media$/i,
  /^\/public$/i,

  // ─── Admin subdirectory exploits (anywhere in path) ──────────────────
  /\/admin\/(uploads?|images|editor|fckeditor|controller)/i,

  // ─── CMS/framework directories (root level) ─────────────────────────
  /^\/modules$/i,
  /^\/plugins$/i,
  /^\/components$/i,
  /^\/system$/i,
  /^\/template$/i,
  /^\/includes?$/i,
  /^\/vendor$/i,
  /^\/local$/i,
  /^\/php$/i,

  // ─── CMS-specific exploit paths (anywhere in path) ──────────────────
  /\/fckeditor\/editor\/filemanager/i,
  /\/sites\/default\/files/i,
  /\/images\/stories/i,
  /\/modules\/mod_simplefileupload/i,
  /\/controller\/extension/i,

  // ─── WYSIWYG editor exploits ────────────────────────────────────────
  /\/ckeditor/i,
  /\/tinymce/i,
  /\/elfinder/i,

  // ─── Admin panels (exact matches) ───────────────────────────────────
  /^\/admin(\.php)?$/i,
  /^\/administrator/i,
  /^\/phpmyadmin/i,
  /^\/cpanel/i,
  /^\/whm/i,
  /^\/cgi-bin/i,

  // ─── CMS frameworks (anchored to root) ──────────────────────────────
  /^\/typo3/i,
  /^\/joomla/i,
  /^\/drupal/i,
  /^\/magento/i,

  // ─── Magento 2 REST API fingerprint probes ────────────────────────────
  // Scanners hit `/rest/V1/store/storeConfigs` (and store-scope variants
  // `/rest/default/V1/...`, `/rest/all/V1/...`, `/rest/<store_code>/V1/...`)
  // to fingerprint Magento installs and chain known CVEs. Without this
  // entry the probe 404s with no strike, letting a scanner sweep forever.
  // The `/i` flag matches both `/V1/` and `/v1/`. Optional non-capturing
  // scope segment matches both `/rest/v1/...` and `/rest/<scope>/v1/...`.
  /^\/rest\/(?:[a-z0-9_-]+\/)?v\d+(?:\/|$)/i,

  // ─── Version control directories ────────────────────────────────────
  /\/\.git/i,
  /\/\.svn/i,
  /\/\.hg/i,

  // ─── Config/sensitive files (anywhere in path) ──────────────────────
  /\/\.env/i,
  /\/\.sql$/i,
  /\/(vendor|node_modules)\//i,
  /\/\.htaccess$/i,
  /\/\.htpasswd$/i,

  // ─── OS metadata files ──────────────────────────────────────────────
  /\/\.DS_Store$/i,
  /\/Thumbs\.db$/i,

  // ─── SSH/credential files ───────────────────────────────────────────
  /\/\.ssh/i,
  /\/id_rsa/i,
  /\/id_ed25519/i,
  /\/\.npmrc$/i,
  /\/\.pypirc$/i,
  /\/\.aws\//i,

  // ─── Backup files (.bak, .old, .backup, .orig, .save, .swp) ────────
  /\.(bak|old|backup|orig|save|swp)$/i,

  // ─── Compressed archives ───────────────────────────────────────────
  /\.(7z|tgz|tar\.gz|tar|bz2|war|jar)$/i,

  // ─── Config files at root (NOT /api/*/config.json) ──────────────────
  /^\/config\.(js|json|yml|yaml|xml|ini|conf)$/i,
  /^\/settings\.(js|json|yml|yaml|xml)$/i,
  /^\/credentials\.(js|json|yml|yaml)$/i,
  /^\/secrets\.(js|json|yml|yaml|env)$/i,
  /^\/appsettings\.(json|yml|yaml)$/i,
  /^\/application\.(yml|yaml|xml|properties)$/i,

  // ─── FTP/SFTP config files ──────────────────────────────────────────
  /sftp-config\.json$/i,
  /ftpsync\.settings$/i,
  /\.ftpconfig$/i,
  /\.ftppass$/i,
  /\.remote-sync\.json$/i,
  /ftp-deploy\.json$/i,

  // ─── JS files at root that leak app structure ───────────────────────
  /^\/env\.js$/i,
  /^\/main\.js$/i,
  /^\/index\.js$/i,
  /^\/app\.js$/i,

  // ─── Server info/status routes ──────────────────────────────────────
  /^\/server-(status|info)$/i,
  /^\/info$/i,

  // ─── Swagger/OpenAPI probes (NOT /api/openapi.json or nested API docs) ─
  /^\/swagger/i,
  /^\/api\/swagger\.(json|yml|yaml)$/i,
  /^\/api-docs/i,
  /^\/v\d+\/api-docs/i,

  // ─── Environment leak attempts ──────────────────────────────────────
  /^\/_env/i,
  /^\/env$/i,
  /^\/config\//i,

  // ─── Backup patterns (anchored to root) ─────────────────────────────
  /^\/backup/i,
  /^\/bk$/i,
  /^\/bak$/i,
  /^\/bac$/i,
  /^\/dump/i,

  // ─── Database patterns (anchored to root) ───────────────────────────
  /^\/db_/i,
  /^\/sql/i,

  // ─── Shell/exploit patterns (anchored to root) ──────────────────────
  /^\/shell/i,

  // ─── Brute force discovery patterns (exact matches) ─────────────────
  /^\/old$/i,
  /^\/new$/i,
  /^\/test$/i,
  /^\/demo$/i,
  /^\/www$/i,
  /^\/main$/i,
  /^\/site$/i,
  /^\/shop$/i,
  /^\/bc$/i,
  /^\/sitio$/i,
  /^\/sito$/i,
  /^\/oldsite$/i,
  /^\/old-site$/i,
  /^\/script$/i,
  /^\/\d{4}$/i,

  // ─── Command injection probes ───────────────────────────────────────
  /^\/getcmd$/i,
  /\$\(/,
  /`/,
  /"/,
  /\{(curl|wget|bash|sh|nc|ncat|python|perl|ruby|php),/i, // Brace expansion injection ({curl,URL} bypasses WAFs)
  /\.oast\.(site|fun|live|me|online|pro)/i, // OAST callback domains (Interactsh/Burp Collaborator exfiltration)
  /(%00|\x00)/, // Null byte injection (encoded and decoded forms)

  // ─── Zero-width / invisible Unicode normalisation probes ─────────────
  // Scanners send paths like `/%E2%80%8B` (U+200B Zero-Width Space) to
  // hunt URL-normalisation bugs in routers and CDNs. Hono decodes
  // `c.req.path`, so these arrive as literal Unicode chars. The range
  // covers ZWSP, ZWNJ, ZWJ, LRM, RLM, LRO, RLO, all spaces and dashes
  // in U+2000–U+203F General Punctuation, plus the U+FEFF UTF-8 BOM.
  // Real users never type these into a URL bar.
  /[\u2000-\u203F\uFEFF]/u,

  // ─── Appliance / storage / NAS exploit probes ──────────────────────
  /^\/storfs-asup$/i, // NetApp StorageGRID ASUP endpoint fingerprint

  // ─── JS framework fingerprinting (Next.js, Nuxt, React, Vercel) ────
  /^\/_next/i,
  /^\/_rsc/i,
  /^\/__rsc/i,
  /^\/_vercel/i,
  /next\.config\.(js|mjs|ts)$/i,
  /nuxt\.config\.(js|ts)$/i,
  /craco\.config\.js$/i,

  // ─── Deployment/infra config probes ─────────────────────────────────
  /serverless\.(yml|yaml|json)$/i,
  /vercel\.json$/i,
  /netlify\.toml$/i,
  /\/helm\//i,

  // ─── Package manager/dependency files ───────────────────────────────
  /\/package\.json$/i,
  /\/composer\.(json|lock)$/i,
  /\/Gemfile(\.lock)?$/i,
  /\/requirements\.txt$/i,

  // ─── Docker/container config probes ─────────────────────────────────
  /docker-compose\.(yml|yaml)$/i,
  /Dockerfile$/i,
  /\/docker\//i,

  // ─── AWS/cloud credential probes ────────────────────────────────────
  /^\/aws/i,
  /\/aws[_-]s3/i,
  /\/aws[_-]ses/i,

  // ─── Path traversal / local file inclusion (LFI) ─────────────────────
  /\.\.\//,
  /\.\.%2f/i,
  /\.\.%5c/i,
  /^\/etc\//i,
  /^\/proc\//i,
  /^\/var\//i,
  /^\/opt\//i,
  /\/passwd$/i,

  // ─── Log file probes ───────────────────────────────────────────────
  /\.log$/i,
  /\/error_log$/i,

  // ─── Vite / dev server exploits (CVE-2025-30208) ────────────────────
  /^\/@fs\//i,
  /^\/@vite\//i,
  /^\/@id\//i,

  // ─── Laravel/Django debug probes ───────────────────────────────────
  /^\/_ignition/i,
  /^\/__debug__/i,

  // ─── Java/Tomcat/Solr/Spring Boot probes ───────────────────────────
  /\/WEB-INF/i,
  /^\/manager\/html/i,
  /^\/solr/i,
  /^\/actuator/i,
  /\/elmah\.axd$/i,
  /^\/servlet\//i,
  /bsh\.servlet/i,
  /^\/struts\//i,
  /^\/invoker\//i,
  /\.action$/i,

  // ─── Mail server / webmail probes ──────────────────────────────────
  /\/mailcow/i,
  /^\/roundcube\//i,
  /^\/webmail\//i,

  // ─── Database admin tool aliases ───────────────────────────────────
  /^\/adminer/i,
  /^\/pma\//i,
  /^\/myadmin\//i,
  /^\/mysqladmin/i,
  /^\/dbadmin/i,

  // ─── Open-proxy discovery probes ─────────────────────────────────
  /^\/ip$/i, // httpbin-style IP echo, fingerprints open forward proxies
  /^\/proxy\.pac$/i, // WPAD proxy auto-config probe

  // ─── SSRF / cloud metadata probes ─────────────────────────────────
  /^\/proxy\//i,
  /169\.254\.169\.254/,
  /^\/latest\/meta-data/i,

  // ─── IoT / Router exploits (Mirai/Muhstik botnets) ────────────────
  /^\/HNAP1\//i,
  /^\/boaform\//i,
  /^\/GponForm\//i,
  /\.cgi$/i, // CGI scripts (router exploits: /apply_sec.cgi Zyxel, /setup.cgi Netgear, /tmUnblock.cgi, etc.)
  /\.htm$/i, // Router/legacy admin panels (e.g. /hw-sys.htm Huawei). Exclude if your app serves .htm files.

  // ─── VMware / virtualization probes ───────────────────────────────
  /^\/sdk$/i, // VMware vCenter SDK endpoint
  /^\/websso\//i, // VMware SSO login

  // ─── Microsoft Exchange / SharePoint webshell paths ───────────────
  /^\/owa\//i,
  /^\/aspnet_client\//i,
  /^\/autodiscover\//i,
  /^\/ecp\//i,
  /^\/_layouts\//i,
  /^\/_vti_bin\//i,

  // ─── File transfer / self-hosted app probes ───────────────────────
  /^\/WebInterface\//i,
  /^\/owncloud\//i,
  /^\/nextcloud\//i,

  // ─── Self-hosted collaboration / monitoring ───────────────────────
  /^\/geoserver\//i,
  /^\/geowebcache\//i,
  /^\/confluence\//i,
  /^\/jira\//i,
  /^\/grafana\//i,
  /^\/kibana\//i,
  /^\/prometheus\//i,

  // ─── CI/CD / DevOps tool probes ───────────────────────────────────
  /^\/jenkins\//i,
  /\/j_acegi_security_check/i,
  /^\/portainer\//i,
  /^\/gitea\//i,
  /^\/gitlab\//i,

  // ─── Infra / container / Kubernetes probes ────────────────────────
  /^\/metrics$/i,
  /^\/healthz$/i,
  /^\/readyz$/i,
  /^\/livez$/i,
  /^\/console\//i,
  /^\/debug\//i,
  /^\/\.dockerenv$/i,
];

// ─── Default IP Extraction ──────────────────────────────────────────────

/** Extract client IP from proxy headers (Cloudflare, Nginx, standard proxies) */
function defaultGetIP(c: Context): string {
	return (
		c.req.header('cf-connecting-ip') ||
		c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
		c.req.header('x-real-ip') ||
		'unknown'
	);
}

// ─── Middleware ──────────────────────────────────────────────────────────

/**
 * Create honeypot middleware to block bot attacks and vulnerability scanners
 *
 * Intercepts 200+ common attack patterns (WordPress, PHP, admin panels, framework probes, etc.)
 * before they reach your route handlers. Returns 410 Gone by default for faster search engine
 * deindexing and bot deterrence.
 *
 * When a store is provided, enables IP strike tracking: after N pattern matches (default 3),
 * the IP is banned and ALL subsequent requests return 410 instantly without pattern matching.
 *
 * @param options - Configuration for patterns, store, logging, and status code
 * @returns Hono middleware handler
 *
 * @example
 * Basic usage (stateless, blocks all built-in patterns)
 * ```ts
 * import { Hono } from 'hono'
 * import { honeypot } from 'hono-honeypot'
 *
 * const app = new Hono()
 * app.use('*', honeypot())
 * ```
 *
 * @example
 * With IP banning via MemoryStore
 * ```ts
 * import { honeypot, MemoryStore } from 'hono-honeypot'
 *
 * app.use('*', honeypot({
 *   store: new MemoryStore(),
 *   strikeThreshold: 3,
 * }))
 * ```
 */
export const honeypot = (options: HoneypotOptions = {}) => {
	let patterns = [...ATTACK_PATTERNS, ...(options.patterns || [])];

	if (options.exclude?.length) {
		patterns = patterns.filter(
			(pattern) => !options.exclude!.some((excludePattern) => pattern.source === excludePattern.source),
		);
	}

	const shouldLog = options.log ?? true;
	const status = options.status ?? 410;
	const store = options.store;
	const strikeThreshold = options.strikeThreshold ?? 3;
	const getIP = options.getIP ?? defaultGetIP;
	const onBlocked = options.onBlocked;

	return createMiddleware(async (c, next) => {
		const ip = getIP(c);
		const validIP = ip && ip !== 'unknown';

		// Fast path: check if IP is already banned (skips pattern matching entirely)
		if (store && validIP) {
			if (await store.isBanned(ip)) {
				const path = c.req.path.replace(/\/+/g, '/');
				if (onBlocked) {
					onBlocked({ ip, path, method: c.req.method, reason: 'banned' });
				} else if (shouldLog) {
					console.log(`\u{1F6AB} Banned [${ip}] ${c.req.method} ${path}`);
				}
				return c.body(null, status);
			}
		}

		// Normalize path: collapse double slashes (bots use //admin to bypass)
		const rawPath = c.req.path;
		const path = rawPath.replace(/\/+/g, '/');

		if (patterns.some((pattern) => pattern.test(path))) {
			let strikes: number | undefined;
			let banned = false;

			// Track strikes and ban if threshold reached
			if (store && validIP) {
				strikes = await store.addStrike(ip);
				if (strikes >= strikeThreshold) {
					await store.ban(ip);
					await store.resetStrikes(ip);
					banned = true;
				}
			}

			if (onBlocked) {
				onBlocked({ ip, path, method: c.req.method, reason: 'pattern', strikes, banned });
			} else if (shouldLog) {
				const banMsg = banned ? ` \u{1F6AB} BANNED` : '';
				console.log(`\u{1F36F} Blocked [${ip}] ${c.req.method} ${path}${banMsg}`);
			}

			return c.body(null, status);
		}

		return next();
	});
};
