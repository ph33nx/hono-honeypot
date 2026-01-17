/**
 * hono-honeypot - Zero-dependency security middleware for Hono.js
 * Blocks bot attacks, vulnerability scanners, and brute-force attempts
 *
 * @license MIT
 * @author ph33nx <https://github.com/ph33nx>
 */

import { createMiddleware } from 'hono/factory';

/**
 * Attack patterns to intercept
 *
 * Rules:
 * - ^pattern$ = exact match (e.g., ^\/admin$ matches /admin, not /api/admin)
 * - ^pattern = starts with (e.g., ^\/wp- matches /wp-admin, not /api/wp-admin)
 * - pattern = substring match (use carefully)
 */
const ATTACK_PATTERNS = [
  // PHP patterns
  /\.php$/i,
  /\/config\.php/i,
  /\/phpinfo/i,
  /\/eval-stdin\.php/i,
  /\/xmlrpc\.php/i,

  // WordPress (anchored to root level to avoid catching /api/wordpress-integration)
  /^\/wp$/i,
  /^\/wp-/i,
  /^\/wordpress/i,

  // Admin panels (exact matches)
  /^\/admin(\.php)?$/i,
  /^\/administrator/i,
  /^\/phpmyadmin/i,
  /^\/cpanel/i,
  /^\/whm/i,
  /^\/cgi-bin/i,

  // CMS frameworks (anchored to root)
  /^\/typo3/i,
  /^\/joomla/i,
  /^\/drupal/i,
  /^\/magento/i,

  // Config/sensitive files (anywhere in path is suspicious)
  /\/\.env/i,
  /\/\.git/i,
  /\/\.sql$/i,
  /\/\.well-known\/security\.txt/i,
  /\/(vendor|node_modules)\//i,

  // Backup files (.bak, .old, .backup, .orig)
  /\.(bak|old|backup|orig|save|swp)$/i,

  // Config files at root (NOT /api/*/config.json, only root-level)
  /^\/config\.(js|json|yml|yaml|xml|ini|conf)$/i,
  /^\/settings\.(js|json|yml|yaml|xml)$/i,
  /^\/credentials\.(js|json|yml|yaml)$/i,
  /^\/secrets\.(js|json|yml|yaml|env)$/i,
  /^\/appsettings\.(json|yml|yaml)$/i,
  /^\/application\.(yml|yaml|xml|properties)$/i,

  // JS files at public root
  /^\/env\.js$/i,

  // Server info/status routes
  /^\/server-(status|info)$/i,
  /^\/info$/i,

  // Swagger/OpenAPI at root (NOT /api/openapi.json)
  /^\/swagger\.(json|yml|yaml)$/i,
  /^\/api\/swagger\.(json|yml|yaml)$/i,

  // Environment leak attempts
  /^\/_env/i,
  /^\/config\//i, // /config/secrets.env, /config/database.php.bak

  // Backup patterns (anchored to root to avoid /api/backup-service)
  /^\/backup/i,
  /^\/bk$/i,
  /^\/bak$/i,
  /^\/bac$/i,
  /^\/dump/i,

  // Database patterns (anchored to root)
  /^\/db_/i,
  /^\/sql/i,

  // Shell/exploit patterns (anchored to root)
  /^\/shell/i,

  // Auth routes (exact matches only)
  /^\/login$/i,
  /^\/signin$/i,
  /^\/register$/i,
  /^\/signup$/i,
  /^\/dashboard$/i,
  /^\/user\/(login|signin|register|signup)/i,

  // Brute force discovery patterns (exact matches - year folders like /2017, common test paths)
  /^\/old$/i,
  /^\/new$/i,
  /^\/test$/i,
  /^\/demo$/i,
  /^\/www$/i,
  /^\/main$/i,
  /^\/site$/i,
  /^\/shop$/i,
  /^\/blog$/i, // Exact /blog only (not /blogs)
  /^\/bc$/i,
  /^\/sitio$/i,
  /^\/sito$/i,
  /^\/oldsite$/i,
  /^\/old-site$/i,
  /^\/\d{4}$/i, // 4-digit years: /2017, /2018, etc.
]

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
	 * Log blocked requests to console with 🍯 emoji and client IP
	 *
	 * @default true
	 *
	 * @example
	 * Output: `🍯 Blocked [192.168.1.1] GET /wp-admin`
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
}

/**
 * Create honeypot middleware to block bot attacks and vulnerability scanners
 *
 * Intercepts 80+ common attack patterns (WordPress, PHP, admin panels, etc.) before they reach your route handlers.
 * Returns 410 Gone by default for faster search engine deindexing and bot deterrence.
 *
 * @param options - Configuration for custom patterns, exclusions, logging, and status code
 * @returns Hono middleware handler
 *
 * @example
 * Basic usage (blocks all built-in patterns)
 * ```ts
 * import { Hono } from 'hono'
 * import { honeypot } from 'hono-honeypot'
 *
 * const app = new Hono()
 * app.use('*', honeypot())
 * ```
 *
 * @example
 * With custom patterns and exclusions
 * ```ts
 * app.use('*', honeypot({
 *   patterns: [/^\/secret/i],      // Add custom pattern
 *   exclude: [/^\/admin$/i],       // Allow your /admin route
 *   log: true,                      // Enable logging
 *   status: 410                     // Return 410 Gone
 * }))
 * ```
 */
export const honeypot = (options: HoneypotOptions = {}) => {
	// Start with built-in patterns, add custom patterns, filter out exclusions
	let patterns = [...ATTACK_PATTERNS, ...(options.patterns || [])];

	if (options.exclude?.length) {
		// Remove patterns that match any exclude pattern (by source string comparison)
		patterns = patterns.filter(
			(pattern) => !options.exclude!.some((excludePattern) => pattern.source === excludePattern.source),
		);
	}

	const shouldLog = options.log ?? true;
	const status = options.status ?? 410;

	return createMiddleware(async (c, next) => {
		const path = c.req.path;

		if (patterns.some((pattern) => pattern.test(path))) {
			if (shouldLog) {
				// Extract client IP from proxy headers (Cloudflare, Nginx, standard proxies)
				const ip =
					c.req.header('cf-connecting-ip') ||
					c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
					c.req.header('x-real-ip') ||
					'unknown';
				console.log(`🍯 Blocked [${ip}] ${c.req.method} ${path}`);
			}

			// Empty body reduces bandwidth on high-volume attacks
			return c.body(null, status);
		}

		return next();
	});
};
