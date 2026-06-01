/**
 * hono-honeypot/abuseipdb — optional AbuseIPDB community reporter.
 *
 * Reports IPs that the honeypot bans back to the shared AbuseIPDB abuse
 * database. Wire it into `honeypot({ onBlocked })`. It is intentionally a
 * separate entry point so the core middleware stays zero-dependency and
 * vendor-neutral — import it only if you want AbuseIPDB.
 *
 * Design notes:
 * - **Injectable `fetch`** (the "fetcher"): defaults to `globalThis.fetch`, but
 *   you can pass a bound/service-binding fetch for Workers or a fake for tests.
 * - **Key resolution is edge-portable**: an explicit `apiKey` wins; otherwise it
 *   reads `c.env[envKey]` (Cloudflare Workers / Bun / Deno bindings) and falls
 *   back to `process.env[envKey]` (Node). `process.env` is empty by default on
 *   Workers, which is why context resolution matters.
 * - **Reports once, on ban**: by default only fires when `info.banned === true`,
 *   keeping you well under AbuseIPDB's 1000/day + 15-min-per-IP limits.
 * - **Never throws, never blocks**: fire-and-forget; all failures are logged and
 *   swallowed so the request path is unaffected.
 *
 * @example
 * ```ts
 * import { honeypot, MemoryStore } from 'hono-honeypot';
 * import { abuseIPDBReporter } from 'hono-honeypot/abuseipdb';
 *
 * app.use('*', honeypot({
 *   store: new MemoryStore(),
 *   onBlocked: abuseIPDBReporter(), // reads ABUSEIPDB_API_KEY from c.env / process.env
 * }));
 * ```
 *
 * @see https://docs.abuseipdb.com/
 * @license MIT
 */

import type { Context } from 'hono';
import type { BlockInfo } from './index';

/** AbuseIPDB report endpoint (API v2). */
const DEFAULT_ENDPOINT = 'https://api.abuseipdb.com/api/v2/report';

/** 21 = Web App Attack, 19 = Bad Web Bot (AbuseIPDB category codes). */
const DEFAULT_CATEGORIES = '21,19';

/** Default env var name holding the AbuseIPDB API key. */
const DEFAULT_ENV_KEY = 'ABUSEIPDB_API_KEY';

/**
 * Minimal fetch-like signature for the injected fetcher. Deliberately structural
 * rather than `typeof fetch`, so any fetch-like function works — a Workers service
 * binding, a wrapped/instrumented fetch, or a test fake — without having to carry
 * the global's extra static members (e.g. `preconnect`).
 */
export type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

export interface AbuseIPDBOptions {
	/**
	 * AbuseIPDB API key, or a resolver from the request context.
	 * When omitted, the key is resolved from the environment (see {@link envKey}).
	 */
	apiKey?: string | ((c: Context) => string | undefined);

	/**
	 * Environment variable name to resolve the key from when {@link apiKey} is not given.
	 * Checked on `c.env` first (Workers/Bun/Deno bindings), then `process.env` (Node).
	 * @default 'ABUSEIPDB_API_KEY'
	 */
	envKey?: string;

	/**
	 * Injected fetch implementation (the "fetcher"). Use to pass a bound fetch on
	 * Workers, or a fake in tests. Any fetch-like function is accepted.
	 * @default globalThis.fetch
	 */
	fetch?: Fetcher;

	/**
	 * AbuseIPDB report category ids, comma-separated.
	 * @default '21,19' (Web App Attack, Bad Web Bot)
	 */
	categories?: string;

	/**
	 * Build the public report comment from the block info. The result is sanitized
	 * to printable ASCII and capped before sending. Keep it to the attacker's own
	 * request line — the comment is published publicly on AbuseIPDB.
	 * @default `Honeypot: automated vulnerability scan / web app attack. Last probe: ${method} ${path}`
	 */
	comment?: (info: BlockInfo) => string;

	/**
	 * Decide whether a given block should be reported. Report sparingly to respect
	 * AbuseIPDB rate limits.
	 * @default (info) => info.banned === true
	 */
	reportOn?: (info: BlockInfo) => boolean;

	/**
	 * Override the report endpoint (mainly for testing).
	 * @default 'https://api.abuseipdb.com/api/v2/report'
	 */
	endpoint?: string;
}

/**
 * Resolve the API key: explicit option → `c.env[envKey]` → `process.env[envKey]`.
 */
function resolveKey(c: Context, apiKey: AbuseIPDBOptions['apiKey'], envKey: string): string | undefined {
	if (typeof apiKey === 'function') return apiKey(c);
	if (apiKey) return apiKey;
	// `c.env` holds runtime bindings on Workers/Bun/Deno; undefined on plain Node.
	const fromContext = (c.env as Record<string, string | undefined> | undefined)?.[envKey];
	if (fromContext) return fromContext;
	// Node-style fallback. `process` may be undefined on edge runtimes.
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[envKey];
}

/**
 * Create an `onBlocked`-compatible reporter that submits banned IPs to AbuseIPDB.
 *
 * The returned function is fire-and-forget: it never throws and never blocks the
 * request. Without a resolvable API key (or for `ip === 'unknown'`) it is a no-op,
 * so it is safe to wire up unconditionally.
 */
export function abuseIPDBReporter(
	options: AbuseIPDBOptions = {},
): (info: BlockInfo, c: Context) => Promise<void> {
	const envKey = options.envKey ?? DEFAULT_ENV_KEY;
	const categories = options.categories ?? DEFAULT_CATEGORIES;
	const endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
	const reportOn = options.reportOn ?? ((info: BlockInfo) => info.banned === true);
	const buildComment =
		options.comment ??
		((info: BlockInfo) =>
			`Honeypot: automated vulnerability scan / web app attack. Last probe: ${info.method} ${info.path}`);

	return async (info, c) => {
		if (!reportOn(info)) return;
		if (!info.ip || info.ip === 'unknown') return;

		const key = resolveKey(c, options.apiKey, envKey);
		if (!key) return;

		const doFetch = options.fetch ?? globalThis.fetch;
		if (!doFetch) return;

		// The comment is public: strip to printable ASCII and cap length so we never
		// reflect raw attacker bytes, and never leak our own routes or infrastructure.
		const comment = buildComment(info).replace(/[^\x20-\x7E]/g, '').slice(0, 200);

		try {
			const res = await doFetch(endpoint, {
				method: 'POST',
				headers: {
					Key: key,
					Accept: 'application/json',
					'Content-Type': 'application/x-www-form-urlencoded',
				},
				body: new URLSearchParams({ ip: info.ip, categories, comment }),
			});
			// 429 is expected and harmless (15-min same-IP guard or the 1000/day
			// free-tier cap). We never retry, never throw — just note it.
			if (!res.ok) {
				console.warn('[AbuseIPDB] report not accepted:', res.status);
			}
		} catch (error) {
			console.warn('[AbuseIPDB] report skipped (network error):', error);
		}
	};
}
