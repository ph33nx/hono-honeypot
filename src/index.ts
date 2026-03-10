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
 *
 * Note: Paths are normalized (double slashes collapsed) before matching
 */
const ATTACK_PATTERNS = [
  // PHP patterns
  /\.php$/i,
  /\/config\.php/i,
  /\/phpinfo/i,
  /\/eval-stdin\.php/i,
  /\/xmlrpc\.php/i,

  // Shell/backdoor patterns (anywhere in path)
  /\/ALFA_DATA/i,
  /\/c99\.php/i,
  /\/r57\.php/i,
  /\/shell\.php/i,
  /\/webshell/i,

  // WordPress (anchored to root level to avoid catching /api/wordpress-integration)
  /^\/wp$/i,
  /^\/wp-/i,
  /^\/wordpress/i,

  // WordPress internals (anywhere in path - these are ALWAYS attack probes)
  /\/wp-includes\//i,
  /\/wp-content\//i,
  /\/wp-admin/i,
  /wlwmanifest\.xml$/i, // Windows Live Writer manifest - WordPress-specific

  // Generic upload/file directories (root level)
  /^\/uploads?$/i,
  /^\/images$/i,
  /^\/assets$/i,
  /^\/files$/i,
  /^\/media$/i,
  /^\/public$/i,

  // Admin subdirectories (common exploit paths)
  /\/admin\/(uploads?|images|editor|fckeditor|controller)/i,

  // CMS/framework directories (root level)
  /^\/modules$/i,
  /^\/plugins$/i,
  /^\/components$/i,
  /^\/system$/i,
  /^\/template$/i,
  /^\/includes?$/i,
  /^\/vendor$/i,
  /^\/local$/i,
  /^\/php$/i,

  // CMS-specific exploit paths (anywhere in path)
  /\/fckeditor\/editor\/filemanager/i, // FCKeditor file upload exploit
  /\/sites\/default\/files/i, // Drupal
  /\/images\/stories/i, // Joomla
  /\/modules\/mod_simplefileupload/i, // Joomla upload exploit
  /\/controller\/extension/i, // OpenCart

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

  // FTP/SFTP config files (credential leak probes)
  /sftp-config\.json$/i,
  /ftpsync\.settings$/i,
  /\.ftpconfig$/i,
  /\.ftppass$/i,
  /\.remote-sync\.json$/i,
  /ftp-deploy\.json$/i,

  // JS files at root that leak environment info
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

  // Brute force discovery patterns (exact matches - year folders like /2017, common test paths)
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
  /^\/\d{4}$/i, // 4-digit years: /2017, /2018, etc.

  // Command injection probes
  /^\/getcmd$/i,

  // ─── JS framework fingerprinting (Next.js, Nuxt, React, Vercel) ─────
  // Probes for framework internals - bots scanning for Next/Nuxt/React apps
  /^\/_next/i,
  /^\/_rsc/i,
  /^\/__rsc/i,
  /^\/_vercel/i,
  /next\.config\.(js|mjs|ts)$/i,
  /nuxt\.config\.(js|ts)$/i,
  /craco\.config\.js$/i,

  // ─── Deployment/infra config probes ─────────────────────────────────
  // Serverless, Vercel, Netlify, Helm configs should never be web-accessible
  /serverless\.(yml|yaml|json)$/i,
  /vercel\.json$/i,
  /netlify\.toml$/i,
  /\/helm\//i,

  // ─── Package manager files ─────────────────────────────────────────
  // Bots probe for dependency info to find vulnerable packages
  /\/package\.json$/i,

  // ─── Docker/container config probes ─────────────────────────────────
  // Dockerfile, compose files, registry configs - infrastructure leak attempts
  /docker-compose\.(yml|yaml)$/i,
  /Dockerfile$/i,
  /\/docker\//i,

  // ─── AWS/cloud credential probes ────────────────────────────────────
  // S3 buckets, SES smtp, cloud configs - credential leak attempts
  /^\/aws/i,
  /\/aws[_-]s3/i,
  /\/aws[_-]ses/i,

  // ─── System path traversal probes ───────────────────────────────────
  // /var/task/ (Lambda), /var/log/ (syslog), /opt/ (system packages) - never web-accessible
  /^\/var\//i,
  /^\/opt\//i,

  // ─── Command injection via URL path ─────────────────────────────────
  // $(cmd) and backtick patterns in URLs are always malicious
  /\$\(/,
  /`/,

  // ─── Log file probes ───────────────────────────────────────────────
  // .log files, error_log - application log leak attempts
  /\.log$/i,
  /\/error_log$/i,

  // ─── Java/Tomcat/Solr probes ────────────────────────────────────────
  // WEB-INF, Tomcat manager, Solr admin - Java app server exploit attempts
  /\/WEB-INF/i,
  /^\/manager\/html/i,
  /^\/solr/i,

  // ─── Mail server config probes ──────────────────────────────────────
  /\/mailcow/i,
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
		// Normalize path: collapse double slashes to single (bots use //blog/... to bypass)
		const rawPath = c.req.path;
		const path = rawPath.replace(/\/+/g, '/');

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
