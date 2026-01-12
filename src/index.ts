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
	// PHP
	/\.php$/i,
	/\/config\.php/i,
	/\/phpinfo/i,
	/\/eval-stdin\.php/i,
	/\/xmlrpc\.php/i,

	// WordPress
	/^\/wp$/i,
	/^\/wp-/i,
	/^\/wordpress/i,

	// Admin panels
	/^\/admin(\.php)?$/i,
	/^\/administrator/i,
	/^\/phpmyadmin/i,
	/^\/cpanel/i,
	/^\/whm/i,
	/^\/cgi-bin/i,

	// CMS frameworks
	/^\/typo3/i,
	/^\/joomla/i,
	/^\/drupal/i,
	/^\/magento/i,

	// Sensitive files
	/\/\.env/i,
	/\/\.git/i,
	/\/\.sql$/i,
	/\/\.well-known\/security\.txt/i,
	/\/(vendor|node_modules)\//i,

	// Backup patterns
	/^\/backup/i,
	/^\/bk$/i,
	/^\/bak$/i,
	/^\/bac$/i,
	/^\/dump/i,

	// Database
	/^\/db_/i,
	/^\/sql/i,

	// Shell/exploits
	/^\/shell/i,

	// Auth routes
	/^\/login$/i,
	/^\/signin$/i,
	/^\/register$/i,
	/^\/signup$/i,
	/^\/dashboard$/i,
	/^\/user\/(login|signin|register|signup)/i,

	// Discovery patterns
	/^\/old$/i,
	/^\/new$/i,
	/^\/test$/i,
	/^\/demo$/i,
	/^\/www$/i,
	/^\/main$/i,
	/^\/site$/i,
	/^\/shop$/i,
	/^\/blog$/i,
	/^\/bc$/i,
	/^\/sitio$/i,
	/^\/sito$/i,
	/^\/oldsite$/i,
	/^\/old-site$/i,
	/^\/\d{4}$/i, // Year folders: /2017, /2018, etc.
];

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
