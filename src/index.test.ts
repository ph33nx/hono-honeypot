import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { honeypot } from './index';

describe('honeypot middleware', () => {
	it('blocks WordPress paths', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		const res = await app.request('/wp-admin');
		expect(res.status).toBe(410);
	});

	it('blocks PHP files', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		const res = await app.request('/config.php');
		expect(res.status).toBe(410);
	});

	it('blocks admin panel attempts', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		const res = await app.request('/admin');
		expect(res.status).toBe(410);
	});

	it('allows legitimate routes', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('/api/admin', (c) => c.text('OK'));

		const res = await app.request('/api/admin');
		expect(res.status).toBe(200);
		expect(await res.text()).toBe('OK');
	});

	it('allows /blogs but blocks /blog', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('/blogs', (c) => c.text('Blogs'));

		const blogsRes = await app.request('/blogs');
		expect(blogsRes.status).toBe(200);

		const blogRes = await app.request('/blog');
		expect(blogRes.status).toBe(410);
	});

	it('supports custom patterns', async () => {
		const app = new Hono();
		app.use(
			'*',
			honeypot({
				patterns: [/^\/secret/i],
				log: false,
			})
		);
		app.get('*', (c) => c.text('OK'));

		const res = await app.request('/secret');
		expect(res.status).toBe(410);
	});

	it('supports custom status codes', async () => {
		const app = new Hono();
		app.use('*', honeypot({ status: 403, log: false }));
		app.get('*', (c) => c.text('OK'));

		const res = await app.request('/wp-admin');
		expect(res.status).toBe(403);
	});

	it('blocks year folders', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		const res2017 = await app.request('/2017');
		expect(res2017.status).toBe(410);

		const res2024 = await app.request('/2024');
		expect(res2024.status).toBe(410);

		// Should NOT block non-year patterns
		const resAbcd = await app.request('/abcd');
		expect(resAbcd.status).toBe(200);

		const res12345 = await app.request('/12345');
		expect(res12345.status).toBe(200);
	});

	it('allows excluding built-in patterns', async () => {
		const app = new Hono();
		app.use(
			'*',
			honeypot({
				exclude: [/^\/admin(\.php)?$/i], // Allow /admin for own dashboard (exact pattern match)
				log: false,
			})
		);
		app.get('/admin', (c) => c.text('Admin Dashboard'));
		app.get('*', (c) => c.text('OK'));

		// /admin should now be allowed
		const adminRes = await app.request('/admin');
		expect(adminRes.status).toBe(200);
		expect(await adminRes.text()).toBe('Admin Dashboard');

		// But other admin patterns still blocked
		const phpmyadminRes = await app.request('/phpmyadmin');
		expect(phpmyadminRes.status).toBe(410);
	});
});
