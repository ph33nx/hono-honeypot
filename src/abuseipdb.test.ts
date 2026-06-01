import { describe, it, expect } from 'bun:test';
import type { Context } from 'hono';
import { abuseIPDBReporter } from './abuseipdb';
import type { Fetcher } from './abuseipdb';
import type { BlockInfo } from './index';

// ─── Helpers ────────────────────────────────────────────────────────────

function makeInfo(overrides: Partial<BlockInfo> = {}): BlockInfo {
	return {
		ip: '203.0.113.7',
		path: '/wp-login.php',
		method: 'GET',
		reason: 'pattern',
		strikes: 3,
		banned: true,
		...overrides,
	};
}

/** Minimal Context stub — the reporter only touches `c.env`. */
function ctx(env?: Record<string, string | undefined>): Context {
	return { env } as unknown as Context;
}

interface Recorded {
	url: string;
	init: RequestInit;
	body: URLSearchParams;
}

function fakeFetch(status = 200) {
	const calls: Recorded[] = [];
	const fetch: Fetcher = async (input, init) => {
		calls.push({
			url: String(input),
			init: init ?? {},
			body: init?.body as URLSearchParams,
		});
		// Real Response — `.ok` is derived from the status, no partial-object cast.
		return new Response(null, { status });
	};
	return { calls, fetch };
}

// ─── Tests ──────────────────────────────────────────────────────────────

describe('abuseIPDBReporter', () => {
	it('is a no-op when no key can be resolved', async () => {
		const { calls, fetch } = fakeFetch();
		const report = abuseIPDBReporter({ fetch });
		await report(makeInfo(), ctx()); // no env, no apiKey
		expect(calls).toHaveLength(0);
	});

	it('reports on ban with an explicit key, hitting the report endpoint', async () => {
		const { calls, fetch } = fakeFetch();
		const report = abuseIPDBReporter({ apiKey: 'k3y', fetch });
		await report(makeInfo(), ctx());

		expect(calls).toHaveLength(1);
		expect(calls[0].url).toBe('https://api.abuseipdb.com/api/v2/report');
		expect(calls[0].init.method).toBe('POST');
		expect((calls[0].init.headers as Record<string, string>).Key).toBe('k3y');
		expect((calls[0].init.headers as Record<string, string>)['Content-Type']).toBe(
			'application/x-www-form-urlencoded',
		);
		expect(calls[0].body.get('ip')).toBe('203.0.113.7');
		expect(calls[0].body.get('categories')).toBe('21,19');
		expect(calls[0].body.get('comment')).toContain('GET /wp-login.php');
	});

	it('does not report when the block did not result in a ban (default reportOn)', async () => {
		const { calls, fetch } = fakeFetch();
		const report = abuseIPDBReporter({ apiKey: 'k3y', fetch });
		await report(makeInfo({ banned: false }), ctx());
		expect(calls).toHaveLength(0);
	});

	it('does not report banned IPs that are "unknown"', async () => {
		const { calls, fetch } = fakeFetch();
		const report = abuseIPDBReporter({ apiKey: 'k3y', fetch });
		await report(makeInfo({ ip: 'unknown' }), ctx());
		expect(calls).toHaveLength(0);
	});

	it('resolves the key from c.env (Workers/Bun/Deno bindings)', async () => {
		const { calls, fetch } = fakeFetch();
		const report = abuseIPDBReporter({ fetch });
		await report(makeInfo(), ctx({ ABUSEIPDB_API_KEY: 'from-env' }));
		expect(calls).toHaveLength(1);
		expect((calls[0].init.headers as Record<string, string>).Key).toBe('from-env');
	});

	it('supports a custom envKey', async () => {
		const { calls, fetch } = fakeFetch();
		const report = abuseIPDBReporter({ envKey: 'MY_KEY', fetch });
		await report(makeInfo(), ctx({ MY_KEY: 'custom' }));
		expect(calls).toHaveLength(1);
		expect((calls[0].init.headers as Record<string, string>).Key).toBe('custom');
	});

	it('resolves the key from an apiKey resolver function', async () => {
		const { calls, fetch } = fakeFetch();
		const report = abuseIPDBReporter({
			apiKey: (c) => (c.env as { ABUSEIPDB_API_KEY?: string }).ABUSEIPDB_API_KEY,
			fetch,
		});
		await report(makeInfo(), ctx({ ABUSEIPDB_API_KEY: 'via-fn' }));
		expect(calls).toHaveLength(1);
		expect((calls[0].init.headers as Record<string, string>).Key).toBe('via-fn');
	});

	it('strips non-ASCII bytes and caps the comment at 200 chars', async () => {
		const { calls, fetch } = fakeFetch();
		const report = abuseIPDBReporter({
			apiKey: 'k3y',
			fetch,
			comment: () => '​\u{1F600}café-' + 'A'.repeat(300),
		});
		await report(makeInfo(), ctx());
		const comment = calls[0].body.get('comment')!;
		expect(comment.length).toBe(200);
		// zero-width, emoji, and the é are stripped; the ASCII tail survives.
		expect(comment.startsWith('caf-A')).toBe(true);
	});

	it('honors a custom reportOn predicate', async () => {
		const { calls, fetch } = fakeFetch();
		const report = abuseIPDBReporter({ apiKey: 'k3y', fetch, reportOn: () => true });
		await report(makeInfo({ banned: false }), ctx());
		expect(calls).toHaveLength(1);
	});

	it('honors custom categories and endpoint', async () => {
		const { calls, fetch } = fakeFetch();
		const report = abuseIPDBReporter({
			apiKey: 'k3y',
			fetch,
			categories: '21',
			endpoint: 'https://example.test/report',
		});
		await report(makeInfo(), ctx());
		expect(calls[0].url).toBe('https://example.test/report');
		expect(calls[0].body.get('categories')).toBe('21');
	});

	it('swallows a non-ok response without throwing', async () => {
		const { fetch } = fakeFetch(429);
		const report = abuseIPDBReporter({ apiKey: 'k3y', fetch });
		await expect(report(makeInfo(), ctx())).resolves.toBeUndefined();
	});

	it('swallows network errors without throwing', async () => {
		const fetch = (async () => {
			throw new Error('network down');
		}) as unknown as typeof globalThis.fetch;
		const report = abuseIPDBReporter({ apiKey: 'k3y', fetch });
		await expect(report(makeInfo(), ctx())).resolves.toBeUndefined();
	});
});
