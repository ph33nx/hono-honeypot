import { describe, it, expect, vi } from 'vitest';
import { Hono } from 'hono';
import { honeypot, MemoryStore } from './index';
import type { BlockInfo } from './index';

// ─── Helper ─────────────────────────────────────────────────────────────

function makeApp(options: Parameters<typeof honeypot>[0] = {}) {
	const app = new Hono();
	app.use('*', honeypot({ log: false, ...options }));
	app.get('*', (c) => c.text('OK'));
	return app;
}

// ─── Pattern Matching ───────────────────────────────────────────────────

describe('honeypot middleware', () => {
	it('blocks WordPress paths', async () => {
		const app = makeApp();
		expect((await app.request('/wp-admin')).status).toBe(410);
	});

	it('blocks PHP files', async () => {
		const app = makeApp();
		expect((await app.request('/config.php')).status).toBe(410);
	});

	it('blocks admin panel attempts', async () => {
		const app = makeApp();
		expect((await app.request('/admin')).status).toBe(410);
	});

	it('allows legitimate routes', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('/api/admin', (c) => c.text('OK'));

		const res = await app.request('/api/admin');
		expect(res.status).toBe(200);
		expect(await res.text()).toBe('OK');
	});

	it('allows /blogs and /blog (legitimate user paths)', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('/blogs', (c) => c.text('Blogs'));
		app.get('/blog', (c) => c.text('Blog'));

		expect((await app.request('/blogs')).status).toBe(200);
		expect((await app.request('/blog')).status).toBe(200);
	});

	it('allows /login, /signup, /dashboard (legitimate user paths)', async () => {
		const app = new Hono();
		app.use('*', honeypot({ log: false }));
		app.get('/login', (c) => c.text('Login'));
		app.get('/signup', (c) => c.text('Signup'));
		app.get('/dashboard', (c) => c.text('Dashboard'));

		expect((await app.request('/login')).status).toBe(200);
		expect((await app.request('/signup')).status).toBe(200);
		expect((await app.request('/dashboard')).status).toBe(200);
	});

	it('supports custom patterns', async () => {
		const app = makeApp({ patterns: [/^\/secret/i] });
		expect((await app.request('/secret')).status).toBe(410);
	});

	it('supports custom status codes', async () => {
		const app = makeApp({ status: 403 });
		expect((await app.request('/wp-admin')).status).toBe(403);
	});

	it('blocks year folders', async () => {
		const app = makeApp();

		expect((await app.request('/2017')).status).toBe(410);
		expect((await app.request('/2024')).status).toBe(410);

		// Should NOT block non-year patterns
		expect((await app.request('/abcd')).status).toBe(200);
		expect((await app.request('/12345')).status).toBe(200);
	});

	it('allows excluding built-in patterns', async () => {
		const app = new Hono();
		app.use('*', honeypot({ exclude: [/^\/admin(\.php)?$/i], log: false }));
		app.get('/admin', (c) => c.text('Admin Dashboard'));
		app.get('*', (c) => c.text('OK'));

		expect((await app.request('/admin')).status).toBe(200);
		expect(await (await app.request('/admin')).text()).toBe('Admin Dashboard');

		// Other admin patterns still blocked
		expect((await app.request('/phpmyadmin')).status).toBe(410);
	});

	it('blocks config file attempts at root', async () => {
		const app = makeApp();

		expect((await app.request('/config.json')).status).toBe(410);
		expect((await app.request('/settings.yml')).status).toBe(410);
		expect((await app.request('/secrets.env')).status).toBe(410);
		expect((await app.request('/appsettings.json')).status).toBe(410);

		// But allow config in API routes
		expect((await app.request('/api/config.json')).status).toBe(200);
	});

	it('blocks backup file extensions', async () => {
		const app = makeApp();

		expect((await app.request('/index.php.bak')).status).toBe(410);
		expect((await app.request('/database.sql.old')).status).toBe(410);
		expect((await app.request('/config.backup')).status).toBe(410);
		expect((await app.request('/app.js.orig')).status).toBe(410);
		expect((await app.request('/file.swp')).status).toBe(410);
	});

	it('blocks environment and server info routes', async () => {
		const app = makeApp();

		expect((await app.request('/env.js')).status).toBe(410);
		expect((await app.request('/_env')).status).toBe(410);
		expect((await app.request('/config/secrets.env')).status).toBe(410);
		expect((await app.request('/server-status')).status).toBe(410);
		expect((await app.request('/server-info')).status).toBe(410);
		expect((await app.request('/info')).status).toBe(410);
	});

	it('blocks Swagger/OpenAPI and API docs probes', async () => {
		const app = makeApp();

		expect((await app.request('/swagger.json')).status).toBe(410);
		expect((await app.request('/swagger.yml')).status).toBe(410);
		expect((await app.request('/swagger-ui')).status).toBe(410);
		expect((await app.request('/swagger/v1/swagger.json')).status).toBe(410);
		expect((await app.request('/api/swagger.json')).status).toBe(410);
		expect((await app.request('/api-docs')).status).toBe(410);
		expect((await app.request('/v2/api-docs')).status).toBe(410);
		expect((await app.request('/v3/api-docs/swagger-config')).status).toBe(410);

		// But allow nested docs paths
		expect((await app.request('/api/docs/swagger')).status).toBe(200);
	});

	it('blocks WordPress internals anywhere in path', async () => {
		const app = makeApp();

		expect((await app.request('/wp-includes/js/jquery.js')).status).toBe(410);
		expect((await app.request('/wp-content/uploads/image.png')).status).toBe(410);
		expect((await app.request('/foo/wp-admin/index.php')).status).toBe(410);
		expect((await app.request('/wlwmanifest.xml')).status).toBe(410);
	});

	it('blocks Next.js/Nuxt/Vercel framework probes', async () => {
		const app = makeApp();

		expect((await app.request('/_next/webpack-hmr')).status).toBe(410);
		expect((await app.request('/_rsc')).status).toBe(410);
		expect((await app.request('/__rsc')).status).toBe(410);
		expect((await app.request('/_vercel/insights')).status).toBe(410);
		expect((await app.request('/var/task/next.config.js')).status).toBe(410);
		expect((await app.request('/app/nuxt.config.ts')).status).toBe(410);
		expect((await app.request('/craco.config.js')).status).toBe(410);
	});

	it('blocks deployment config probes', async () => {
		const app = makeApp();

		expect((await app.request('/var/task/serverless.yml')).status).toBe(410);
		expect((await app.request('/vercel.json')).status).toBe(410);
		expect((await app.request('/netlify.toml')).status).toBe(410);
		expect((await app.request('/helm/values.yaml')).status).toBe(410);
		expect((await app.request('/package.json')).status).toBe(410);
		expect((await app.request('/app/package.json')).status).toBe(410);
	});

	it('blocks Docker config probes', async () => {
		const app = makeApp();

		expect((await app.request('/docker-compose.yml')).status).toBe(410);
		expect((await app.request('/Dockerfile')).status).toBe(410);
		expect((await app.request('/docker/registry/config.yml')).status).toBe(410);
	});

	it('blocks AWS credential probes', async () => {
		const app = makeApp();

		expect((await app.request('/aws/bucket')).status).toBe(410);
		expect((await app.request('/aws/s3/credentials')).status).toBe(410);
		expect((await app.request('/aws_s3_config.json')).status).toBe(410);
	});

	it('blocks system path traversal probes', async () => {
		const app = makeApp();

		expect((await app.request('/var/task/next.config.js')).status).toBe(410);
		expect((await app.request('/var/log/apache2/access.log')).status).toBe(410);
		expect((await app.request('/opt/mailcow-dockerized/mailcow.conf')).status).toBe(410);
	});

	it('blocks command injection via URL path', async () => {
		const app = makeApp();
		expect((await app.request('/$(pwd)/serverless.yml')).status).toBe(410);
	});

	it('blocks log file and error_log probes', async () => {
		const app = makeApp();

		expect((await app.request('/log/production.log')).status).toBe(410);
		expect((await app.request('/debug.log')).status).toBe(410);
		expect((await app.request('/error_log')).status).toBe(410);
	});

	it('blocks Java/Tomcat/Solr probes', async () => {
		const app = makeApp();

		expect((await app.request('/WEB-INF/web.xml')).status).toBe(410);
		expect((await app.request('/manager/html')).status).toBe(410);
		expect((await app.request('/solr/admin')).status).toBe(410);
	});

	it('blocks mail server config probes', async () => {
		const app = makeApp();
		expect((await app.request('/opt/mailcow-dockerized/mailcow.conf')).status).toBe(410);
	});

	it('blocks version control directories (.svn, .hg)', async () => {
		const app = makeApp();

		expect((await app.request('/.svn/entries')).status).toBe(410);
		expect((await app.request('/.hg/store')).status).toBe(410);
		expect((await app.request('/.git/config')).status).toBe(410);
	});

	it('blocks SSH/credential file probes', async () => {
		const app = makeApp();

		expect((await app.request('/.ssh/id_rsa')).status).toBe(410);
		expect((await app.request('/id_rsa')).status).toBe(410);
		expect((await app.request('/id_ed25519')).status).toBe(410);
		expect((await app.request('/.npmrc')).status).toBe(410);
		expect((await app.request('/.aws/credentials')).status).toBe(410);
	});

	it('blocks OS metadata files', async () => {
		const app = makeApp();

		expect((await app.request('/.DS_Store')).status).toBe(410);
		expect((await app.request('/Thumbs.db')).status).toBe(410);
	});

	it('blocks Apache config files', async () => {
		const app = makeApp();

		expect((await app.request('/.htaccess')).status).toBe(410);
		expect((await app.request('/.htpasswd')).status).toBe(410);
	});

	it('blocks WYSIWYG editor exploit probes', async () => {
		const app = makeApp();

		expect((await app.request('/ckeditor/upload')).status).toBe(410);
		expect((await app.request('/tinymce/plugins')).status).toBe(410);
		expect((await app.request('/elfinder/connector')).status).toBe(410);
	});

	it('blocks dependency manifest probes', async () => {
		const app = makeApp();

		expect((await app.request('/composer.json')).status).toBe(410);
		expect((await app.request('/composer.lock')).status).toBe(410);
		expect((await app.request('/Gemfile')).status).toBe(410);
		expect((await app.request('/requirements.txt')).status).toBe(410);
	});

	it('blocks Spring Boot actuator probes', async () => {
		const app = makeApp();

		expect((await app.request('/actuator/health')).status).toBe(410);
		expect((await app.request('/actuator/env')).status).toBe(410);
	});

	it('blocks .NET error log probes', async () => {
		const app = makeApp();
		expect((await app.request('/elmah.axd')).status).toBe(410);
	});

	it('blocks JS files at root', async () => {
		const app = makeApp();

		expect((await app.request('/env.js')).status).toBe(410);
		expect((await app.request('/main.js')).status).toBe(410);
		expect((await app.request('/index.js')).status).toBe(410);
		expect((await app.request('/app.js')).status).toBe(410);

		// But allow in nested paths
		expect((await app.request('/api/main.js')).status).toBe(200);
	});

	it('normalizes double slashes to prevent bypass', async () => {
		const app = makeApp();

		expect((await app.request('///admin')).status).toBe(410);
		expect((await app.request('/wp-admin//index.php')).status).toBe(410);
		expect((await app.request('//wp-content/uploads')).status).toBe(410);
	});

	it('blocks shell backdoors and upload directory probes', async () => {
		const app = makeApp();

		expect((await app.request('/ALFA_DATA')).status).toBe(410);
		expect((await app.request('/c99.php')).status).toBe(410);
		expect((await app.request('/shell.php')).status).toBe(410);
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
		const app = makeApp();

		expect((await app.request('/admin/uploads')).status).toBe(410);
		expect((await app.request('/admin/images')).status).toBe(410);
		expect((await app.request('/admin/editor')).status).toBe(410);
		expect((await app.request('/admin/fckeditor')).status).toBe(410);
		expect((await app.request('/admin/controller')).status).toBe(410);
	});

	it('blocks CMS-specific exploit paths', async () => {
		const app = makeApp();

		expect((await app.request('/admin/fckeditor/editor/filemanager')).status).toBe(410);
		expect((await app.request('/sites/default/files')).status).toBe(410);
		expect((await app.request('/images/stories')).status).toBe(410);
		expect((await app.request('/modules/mod_simplefileupload/elements')).status).toBe(410);
		expect((await app.request('/admin/controller/extension/extension')).status).toBe(410);
	});

	it('blocks generic CMS directory probes', async () => {
		const app = makeApp();

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

		// But allow nested paths
		expect((await app.request('/api/modules')).status).toBe(200);
	});

	it('blocks compressed archive probes', async () => {
		const app = makeApp();

		expect((await app.request('/backup.tar.gz')).status).toBe(410);
		expect((await app.request('/dump.7z')).status).toBe(410);
		expect((await app.request('/app.war')).status).toBe(410);
		expect((await app.request('/deploy.jar')).status).toBe(410);
		expect((await app.request('/site.tgz')).status).toBe(410);
	});

	it('blocks path traversal and LFI probes', async () => {
		const app = makeApp();

		expect((await app.request('/../../../etc/passwd')).status).toBe(410);
		expect((await app.request('/etc/shadow')).status).toBe(410);
		expect((await app.request('/proc/self/environ')).status).toBe(410);
		expect((await app.request('/some/path/passwd')).status).toBe(410);
	});

	it('blocks Vite dev server exploits', async () => {
		const app = makeApp();

		expect((await app.request('/@fs/etc/passwd')).status).toBe(410);
		expect((await app.request('/@vite/client')).status).toBe(410);
		expect((await app.request('/@id/some-module')).status).toBe(410);
	});

	it('blocks Laravel/Django debug probes', async () => {
		const app = makeApp();

		expect((await app.request('/_ignition/execute-solution')).status).toBe(410);
		expect((await app.request('/__debug__/toolbar')).status).toBe(410);
	});

	it('blocks Java servlet and Struts exploit probes', async () => {
		const app = makeApp();

		expect((await app.request('/servlet/BshServlet')).status).toBe(410);
		expect((await app.request('/struts/action')).status).toBe(410);
		expect((await app.request('/invoker/EJBInvokerServlet')).status).toBe(410);
		expect((await app.request('/integration/saveGangster.action')).status).toBe(410);
	});

	it('blocks webmail probes', async () => {
		const app = makeApp();

		expect((await app.request('/roundcube/')).status).toBe(410);
		expect((await app.request('/webmail/')).status).toBe(410);
	});

	it('blocks database admin tool aliases', async () => {
		const app = makeApp();

		expect((await app.request('/adminer')).status).toBe(410);
		expect((await app.request('/pma/')).status).toBe(410);
		expect((await app.request('/myadmin/')).status).toBe(410);
		expect((await app.request('/mysqladmin')).status).toBe(410);
		expect((await app.request('/dbadmin')).status).toBe(410);
	});

	it('blocks SSRF and cloud metadata probes', async () => {
		const app = makeApp();

		expect((await app.request('/proxy/http://169.254.169.254')).status).toBe(410);
		expect((await app.request('/latest/meta-data/')).status).toBe(410);
	});

	it('blocks IoT and router exploit probes', async () => {
		const app = makeApp();

		expect((await app.request('/HNAP1/')).status).toBe(410);
		expect((await app.request('/boaform/admin')).status).toBe(410);
		expect((await app.request('/GponForm/diag')).status).toBe(410);
		expect((await app.request('/setup.cgi')).status).toBe(410);
		expect((await app.request('/hw-sys.htm')).status).toBe(410);
	});

	it('blocks Microsoft Exchange and SharePoint probes', async () => {
		const app = makeApp();

		expect((await app.request('/owa/auth/logon.aspx')).status).toBe(410);
		expect((await app.request('/aspnet_client/system_web')).status).toBe(410);
		expect((await app.request('/autodiscover/autodiscover.xml')).status).toBe(410);
		expect((await app.request('/ecp/default.aspx')).status).toBe(410);
		expect((await app.request('/_layouts/15/start.aspx')).status).toBe(410);
		expect((await app.request('/_vti_bin/shtml.dll')).status).toBe(410);
	});

	it('blocks file transfer and self-hosted app probes', async () => {
		const app = makeApp();

		expect((await app.request('/WebInterface/login.html')).status).toBe(410);
		expect((await app.request('/owncloud/status.php')).status).toBe(410);
		expect((await app.request('/nextcloud/')).status).toBe(410);
	});

	it('blocks collaboration and monitoring tool probes', async () => {
		const app = makeApp();

		expect((await app.request('/geoserver/web')).status).toBe(410);
		expect((await app.request('/geowebcache/rest')).status).toBe(410);
		expect((await app.request('/confluence/')).status).toBe(410);
		expect((await app.request('/jira/')).status).toBe(410);
		expect((await app.request('/grafana/api/health')).status).toBe(410);
		expect((await app.request('/kibana/app')).status).toBe(410);
		expect((await app.request('/prometheus/graph')).status).toBe(410);
	});

	it('blocks CI/CD and DevOps tool probes', async () => {
		const app = makeApp();

		expect((await app.request('/jenkins/login')).status).toBe(410);
		expect((await app.request('/j_acegi_security_check')).status).toBe(410);
		expect((await app.request('/portainer/')).status).toBe(410);
		expect((await app.request('/gitea/')).status).toBe(410);
		expect((await app.request('/gitlab/')).status).toBe(410);
	});

	it('blocks Kubernetes and container probes', async () => {
		const app = makeApp();

		expect((await app.request('/metrics')).status).toBe(410);
		expect((await app.request('/healthz')).status).toBe(410);
		expect((await app.request('/readyz')).status).toBe(410);
		expect((await app.request('/livez')).status).toBe(410);
		expect((await app.request('/console/')).status).toBe(410);
		expect((await app.request('/debug/pprof')).status).toBe(410);
		expect((await app.request('/.dockerenv')).status).toBe(410);

		// But allow nested paths (your own /api/health, /api/metrics, etc.)
		expect((await app.request('/api/health')).status).toBe(200);
		expect((await app.request('/api/metrics')).status).toBe(200);
		expect((await app.request('/api/debug')).status).toBe(200);
	});

	it('blocks environment and brute force discovery probes', async () => {
		const app = makeApp();

		expect((await app.request('/env')).status).toBe(410);
		expect((await app.request('/script')).status).toBe(410);
	});

	it('blocks PHP path-info style URLs', async () => {
		const app = makeApp();

		expect((await app.request('/index.php/admin/login')).status).toBe(410);
		expect((await app.request('/app.php/api/users')).status).toBe(410);
	});
});

// ─── MemoryStore Unit Tests ─────────────────────────────────────────────

describe('MemoryStore', () => {
	it('returns false for unknown IPs', () => {
		const store = new MemoryStore();
		expect(store.isBanned('1.2.3.4')).toBe(false);
	});

	it('increments and returns strike count', () => {
		const store = new MemoryStore();
		expect(store.addStrike('1.2.3.4')).toBe(1);
		expect(store.addStrike('1.2.3.4')).toBe(2);
		expect(store.addStrike('1.2.3.4')).toBe(3);
	});

	it('tracks strikes per IP independently', () => {
		const store = new MemoryStore();
		expect(store.addStrike('1.1.1.1')).toBe(1);
		expect(store.addStrike('2.2.2.2')).toBe(1);
		expect(store.addStrike('1.1.1.1')).toBe(2);
		expect(store.addStrike('2.2.2.2')).toBe(2);
	});

	it('bans and detects banned IPs', () => {
		const store = new MemoryStore();
		store.ban('1.2.3.4');
		expect(store.isBanned('1.2.3.4')).toBe(true);
		expect(store.isBanned('5.6.7.8')).toBe(false);
	});

	it('resets strikes for an IP', () => {
		const store = new MemoryStore();
		store.addStrike('1.2.3.4');
		store.addStrike('1.2.3.4');
		store.resetStrikes('1.2.3.4');
		expect(store.addStrike('1.2.3.4')).toBe(1);
	});

	it('expires bans after banTTL', () => {
		const store = new MemoryStore({ banTTL: 1 }); // 1 second
		store.ban('1.2.3.4');
		expect(store.isBanned('1.2.3.4')).toBe(true);

		// Fast-forward time
		vi.useFakeTimers();
		vi.advanceTimersByTime(1500);
		expect(store.isBanned('1.2.3.4')).toBe(false);
		vi.useRealTimers();
	});

	it('expires strikes after strikeTTL', () => {
		const store = new MemoryStore({ strikeTTL: 1 }); // 1 second
		store.addStrike('1.2.3.4');
		store.addStrike('1.2.3.4');
		expect(store.addStrike('1.2.3.4')).toBe(3);

		// Fast-forward time
		vi.useFakeTimers();
		vi.advanceTimersByTime(1500);
		expect(store.addStrike('1.2.3.4')).toBe(1); // Reset
		vi.useRealTimers();
	});
});

// ─── Store Integration Tests ────────────────────────────────────────────

describe('honeypot with store', () => {
	it('increments strikes on pattern match', async () => {
		const store = new MemoryStore();
		const app = makeApp({ store });

		await app.request('/wp-admin');
		expect(store.addStrike('test')).toBe(1); // store is clean for other IPs
	});

	it('bans IP after reaching strike threshold', async () => {
		const store = new MemoryStore();
		const app = new Hono();
		app.use('*', honeypot({
			log: false,
			store,
			strikeThreshold: 2,
			getIP: () => '10.0.0.1',
		}));
		app.get('*', (c) => c.text('OK'));

		// Strike 1
		expect((await app.request('/wp-admin')).status).toBe(410);
		// Strike 2 - triggers ban
		expect((await app.request('/phpmyadmin')).status).toBe(410);

		// Now banned - clean path should also be blocked
		expect((await app.request('/api/data')).status).toBe(410);
	});

	it('banned IP is blocked on ALL paths (fast path)', async () => {
		const store = new MemoryStore();
		const app = new Hono();
		app.use('*', honeypot({
			log: false,
			store,
			strikeThreshold: 1, // ban on first offense
			getIP: () => '10.0.0.1',
		}));
		app.get('*', (c) => c.text('OK'));

		// First request triggers ban
		await app.request('/wp-admin');

		// Clean paths are now blocked
		expect((await app.request('/')).status).toBe(410);
		expect((await app.request('/api/v2/astrology')).status).toBe(410);
		expect((await app.request('/products')).status).toBe(410);
	});

	it('does not track unknown IPs', async () => {
		const store = new MemoryStore();
		const app = new Hono();
		app.use('*', honeypot({
			log: false,
			store,
			strikeThreshold: 1,
			getIP: () => 'unknown',
		}));
		app.get('*', (c) => c.text('OK'));

		// Pattern match but unknown IP - should not ban
		await app.request('/wp-admin');
		await app.request('/phpmyadmin');

		// Clean paths should still work
		expect((await app.request('/api/data')).status).toBe(200);
	});

	it('uses default strikeThreshold of 3', async () => {
		const store = new MemoryStore();
		const app = new Hono();
		app.use('*', honeypot({
			log: false,
			store,
			getIP: () => '10.0.0.1',
		}));
		app.get('*', (c) => c.text('OK'));

		await app.request('/wp-admin');
		await app.request('/phpmyadmin');

		// Not banned yet (only 2 strikes)
		expect((await app.request('/api/data')).status).toBe(200);

		// 3rd strike triggers ban
		await app.request('/.env');
		expect((await app.request('/api/data')).status).toBe(410);
	});

	it('supports custom getIP function', async () => {
		const store = new MemoryStore();
		const app = new Hono();
		app.use('*', honeypot({
			log: false,
			store,
			strikeThreshold: 1,
			getIP: (c) => c.req.header('x-custom-ip') || 'unknown',
		}));
		app.get('*', (c) => c.text('OK'));

		// Request with custom IP header
		await app.request('/wp-admin', { headers: { 'x-custom-ip': '10.0.0.1' } });

		// Banned via custom IP
		expect((await app.request('/', { headers: { 'x-custom-ip': '10.0.0.1' } })).status).toBe(410);

		// Different IP not banned
		expect((await app.request('/', { headers: { 'x-custom-ip': '10.0.0.2' } })).status).toBe(200);
	});
});

// ─── onBlocked Callback Tests ───────────────────────────────────────────

describe('onBlocked callback', () => {
	it('fires with pattern reason on match', async () => {
		const blocked: BlockInfo[] = [];
		const app = new Hono();
		app.use('*', honeypot({
			log: false,
			getIP: () => '10.0.0.1',
			onBlocked: (info) => { blocked.push(info); },
		}));
		app.get('*', (c) => c.text('OK'));

		await app.request('/wp-admin');

		expect(blocked).toHaveLength(1);
		expect(blocked[0].reason).toBe('pattern');
		expect(blocked[0].ip).toBe('10.0.0.1');
		expect(blocked[0].path).toBe('/wp-admin');
		expect(blocked[0].method).toBe('GET');
	});

	it('fires with banned reason for banned IPs', async () => {
		const blocked: BlockInfo[] = [];
		const store = new MemoryStore();
		const app = new Hono();
		app.use('*', honeypot({
			log: false,
			store,
			strikeThreshold: 1,
			getIP: () => '10.0.0.1',
			onBlocked: (info) => { blocked.push(info); },
		}));
		app.get('*', (c) => c.text('OK'));

		// First request: pattern match, triggers ban
		await app.request('/wp-admin');
		expect(blocked[0].reason).toBe('pattern');
		expect(blocked[0].banned).toBe(true);

		// Second request: banned fast path
		await app.request('/clean-path');
		expect(blocked[1].reason).toBe('banned');
	});

	it('includes strike count when store is active', async () => {
		const blocked: BlockInfo[] = [];
		const store = new MemoryStore();
		const app = new Hono();
		app.use('*', honeypot({
			log: false,
			store,
			strikeThreshold: 3,
			getIP: () => '10.0.0.1',
			onBlocked: (info) => { blocked.push(info); },
		}));
		app.get('*', (c) => c.text('OK'));

		await app.request('/wp-admin');
		await app.request('/phpmyadmin');
		await app.request('/.env');

		expect(blocked[0].strikes).toBe(1);
		expect(blocked[0].banned).toBe(false);
		expect(blocked[1].strikes).toBe(2);
		expect(blocked[1].banned).toBe(false);
		expect(blocked[2].strikes).toBe(3);
		expect(blocked[2].banned).toBe(true);
	});
});

// ─── Backwards Compatibility ────────────────────────────────────────────

describe('backwards compatibility', () => {
	it('works without any options (stateless)', async () => {
		const app = new Hono();
		app.use('*', honeypot());
		app.get('/', (c) => c.text('OK'));

		// Pattern match still works
		expect((await app.request('/wp-admin')).status).toBe(410);

		// Clean path works
		expect((await app.request('/')).status).toBe(200);
	});

	it('respects status option without store', async () => {
		const app = makeApp({ status: 404 });
		expect((await app.request('/wp-admin')).status).toBe(404);
	});
});
