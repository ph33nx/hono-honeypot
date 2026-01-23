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

	it('blocks config file attempts at root', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// Should block root-level config files
		expect((await app.request('/config.json')).status).toBe(410);
		expect((await app.request('/settings.yml')).status).toBe(410);
		expect((await app.request('/secrets.env')).status).toBe(410);
		expect((await app.request('/appsettings.json')).status).toBe(410);

		// But allow config in API routes
		const apiConfig = await app.request('/api/config.json');
		expect(apiConfig.status).toBe(200);
	});

	it('blocks backup file extensions', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// Should block backup file extensions anywhere
		expect((await app.request('/index.php.bak')).status).toBe(410);
		expect((await app.request('/database.sql.old')).status).toBe(410);
		expect((await app.request('/config.backup')).status).toBe(410);
		expect((await app.request('/app.js.orig')).status).toBe(410);
		expect((await app.request('/file.swp')).status).toBe(410);
	});

	it('blocks environment and server info routes', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// Environment files
		expect((await app.request('/env.js')).status).toBe(410);
		expect((await app.request('/_env')).status).toBe(410);
		expect((await app.request('/config/secrets.env')).status).toBe(410);

		// Server info routes
		expect((await app.request('/server-status')).status).toBe(410);
		expect((await app.request('/server-info')).status).toBe(410);
		expect((await app.request('/info')).status).toBe(410);
	});

	it('blocks Swagger/OpenAPI config files', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// Should block root and /api swagger files
		expect((await app.request('/swagger.json')).status).toBe(410);
		expect((await app.request('/swagger.yml')).status).toBe(410);
		expect((await app.request('/api/swagger.json')).status).toBe(410);

		// But allow swagger UI routes
		const swaggerUI = await app.request('/api/docs/swagger');
		expect(swaggerUI.status).toBe(200);
	});

	it('blocks WordPress internals anywhere in path', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// WordPress internals should be blocked even in nested paths
		expect((await app.request('/wp-includes/js/jquery.js')).status).toBe(410);
		expect((await app.request('/wp-content/uploads/image.png')).status).toBe(410);
		expect((await app.request('/foo/wp-admin/index.php')).status).toBe(410);
		expect((await app.request('/wlwmanifest.xml')).status).toBe(410);
	});

	it('blocks env.js at root', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// Should block root-level env.js (environment leak)
		expect((await app.request('/env.js')).status).toBe(410);

		// But allow other JS files (not our business to block)
		const mainJs = await app.request('/main.js');
		expect(mainJs.status).toBe(200);
	});

	it('normalizes double slashes to prevent bypass', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// Double slash bypass attempts should still be blocked
		expect((await app.request('//blog')).status).toBe(410);
		expect((await app.request('///admin')).status).toBe(410);
		expect((await app.request('/wp-admin//index.php')).status).toBe(410);
	});

	it('blocks shell backdoors and upload directory probes', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// Shell backdoors
		expect((await app.request('/ALFA_DATA')).status).toBe(410);
		expect((await app.request('/c99.php')).status).toBe(410);
		expect((await app.request('/shell.php')).status).toBe(410);

		// Upload directories at root
		expect((await app.request('/uploads')).status).toBe(410);
		expect((await app.request('/upload')).status).toBe(410);
		expect((await app.request('/images')).status).toBe(410);
		expect((await app.request('/assets')).status).toBe(410);
		expect((await app.request('/files')).status).toBe(410);

		// But allow in API paths
		expect((await app.request('/api/uploads')).status).toBe(200);
		expect((await app.request('/api/images')).status).toBe(200);
	});

	it('blocks admin subdirectory exploits', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// Admin subdirectories anywhere in path
		expect((await app.request('/admin/uploads')).status).toBe(410);
		expect((await app.request('/admin/images')).status).toBe(410);
		expect((await app.request('/admin/editor')).status).toBe(410);
		expect((await app.request('/admin/fckeditor')).status).toBe(410);
		expect((await app.request('/admin/controller')).status).toBe(410);
	});

	it('blocks CMS-specific exploit paths', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// FCKeditor
		expect((await app.request('/admin/fckeditor/editor/filemanager')).status).toBe(410);

		// Drupal
		expect((await app.request('/sites/default/files')).status).toBe(410);

		// Joomla
		expect((await app.request('/images/stories')).status).toBe(410);
		expect((await app.request('/modules/mod_simplefileupload/elements')).status).toBe(410);

		// OpenCart
		expect((await app.request('/admin/controller/extension/extension')).status).toBe(410);
	});

	it('blocks generic CMS directory probes', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('*', (c) => c.text('OK'));

		// Generic directories at root
		expect((await app.request('/modules')).status).toBe(410);
		expect((await app.request('/plugins')).status).toBe(410);
		expect((await app.request('/components')).status).toBe(410);
		expect((await app.request('/system')).status).toBe(410);
		expect((await app.request('/template')).status).toBe(410);
		expect((await app.request('/include')).status).toBe(410);
		expect((await app.request('/vendor')).status).toBe(410);
		expect((await app.request('/local')).status).toBe(410);
		expect((await app.request('/php')).status).toBe(410);
		expect((await app.request('/public')).status).toBe(410);

		// But allow nested legitimate paths
		expect((await app.request('/api/modules')).status).toBe(200);
	});
});
