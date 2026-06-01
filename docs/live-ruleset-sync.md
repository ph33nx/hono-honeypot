# Live Ruleset Sync — research + future plan

We hand-maintain ~210 attack-path regexes, and the same question keeps resurfacing: why not auto-pull a maintained feed so a fresh framework CVE path lands without cutting a release, and let this grow into a proper WAF? I spent a session running the options down. Short version — nothing drops in cleanly today, and the wordlist feeds people instinctively reach for would torch our false-positive rate. This is the writeup so we stop re-litigating it every quarter: what exists, why it doesn't fit yet, and how I'd build it when it does.

Status: research only, June 2026. No code shipped.

## TL;DR (priority order)

| Question | Answer | Action |
|---|---|---|
| Drop hand-rolled paths for a live WAF feed/engine? | **Not yet.** No JS/edge WAF engine, no consensus path-feed exists. | Keep bundled patterns. Add opt-in sync later. |
| Existing engine to piggyback on? | **Coraza** (Go). Only ships `coraza-proxy-wasm` (Envoy/Traefik/APISIX/ngrok). Not Workers, not npm. | Watch `coraza-node` (preview, not on npm). |
| Ready-made path FEED to auto-fetch? | No CrowdSec-grade one. `path-captures` (MIT, daily, single-infra) is closest. Nuclei = CVE paths (YAML, big). | Optional secondary feeds, curated + allowlisted. |
| Use SecLists/Assetnote/FuzzDB wordlists? | **No** — discovery wordlists = mass false positives as blocklist. | Avoid. |
| If we run behind Envoy/Traefik/APISIX/ngrok? | Those already give CRS WAF. | Middleware not needed there. |
| Build our own live sync? | Yes, eventually — pattern is solved (ad-blocker lists). Must be opt-in + fail-safe. | See Architecture. |

## Why no piggyback today

- **Coraza** = OWASP WAF, Go. WASM build = `proxy-wasm` ABI → Envoy/Traefik3/APISIX/ngrok only. Needs TinyGo, ~MBs. NOT loadable in Cloudflare Workers; NOT an npm module.
- **coraza-node** = preview (Coraza creator, Apr 2026 Medium). NOT published to npm (verified 404). Vercel-tested, not Workers. Rules baked at compile time (no hot reload). → revisit later.
- **OWASP CRS** = the real ruleset (Apache-2.0), but SecLang text. Only a ModSecurity engine runs it. Not a path list. "Paranoia levels" + per-app exclusions = how it controls FP.
- **CrowdSec** = IP reputation + behavior. Needs agent process. AppSec uses own rules, not CRS. BSL license. Node bouncer = IP-only. Not embeddable in zero-dep edge middleware. (Low FP comes from community consensus + canary allowlists — copy the *idea*, not the dep.)

## Path feeds (if we add opt-in sync)

| Feed | Format | Cadence | License | FP risk | Verdict |
|---|---|---|---|---|---|
| SevensRequiem/path-captures | paths.json + all.txt | daily | MIT | low (real traffic) | OK secondary; single-source, may vanish |
| projectdiscovery/nuclei-templates | YAML `http.path` | constant | MIT | low-med | CVE paths; needs parser; big |
| FuzzDB predictable-filepaths | txt | periodic | BSD/CC-BY | med | supplementary only |
| SecLists / Assetnote | wordlists | reg/monthly | MIT/Apache | HIGH | DO NOT use as blocklist |

Bundled `ATTACK_PATTERNS` (current ~210 regex) stay the curated, reviewed core = the **pinned fallback**.

## Architecture (when built) — opt-in, fail-safe

- **Pluggable `RuleStore`** (mirror existing `HoneypotStore` in `src/index.ts`): `get()/set()/getMeta()/setMeta()`. Impls: in-memory (default), Redis/KV, fs (Node). Works on all runtimes via `c.env` bindings.
- **Refresh**: conditional GET (`If-None-Match`/ETag, `If-Modified-Since`) → 304 = cheap. **Refresh-if-stale on request** (`Date.now()-lastFetch > TTL`) + Cloudflare **Cron Trigger** / `c.executionCtx.waitUntil()` for background. NEVER `setInterval` (killed on edge after response).
- **Fail-safe (hard rule)**: fetch fail / bad data → keep **stale cache**; empty cache → use **bundled snapshot**. Never fail-open (let attacks through) AND never block-all. On any doubt, fall back to bundled.
- **Match**: union(bundled, fetched). Keep regex precompiled. Cap total patterns.

## Supply-chain safety (MUST, non-negotiable)

A remote list can inject `.*` (block everything) or a ReDoS regex. Mitigations:
1. **Trusted-URL allowlist** (hardcoded exact URLs, no wildcards/redirects).
2. **Hash/signature verify** before parse (sha256 pinned, or Ed25519/minisign manifest).
3. **Schema caps**: max pattern count, max pattern length, charset allowlist for path patterns.
4. **ReDoS sanitize**: reject nested quantifiers `(x+)+`, `(x*)*`; reject if regex compile > N ms; prefer literal/prefix/Aho-Corasick over free regex for fetched entries.
5. **Pinned snapshot fallback** bundled in package (= current `ATTACK_PATTERNS`).
6. Opt-in only: no network unless the user passes a feed config. Core stays zero-dep.

## False-positive control (the "like CrowdSec" goal)

- Real-traffic feeds (path-captures) > synthetic wordlists (SecLists).
- Keep user `exclude` + allowlist support (already in middleware). Document feed-FP escape hatch.
- Treat fetched entries as **lower trust** than bundled: prefix/exact match, not broad regex.
- No consensus source exists for paths → curation is on us. Start conservative; expand on evidence.

## Decision

Ship nothing now. When prioritized: opt-in `hono-honeypot/rules-sync` subpath (separate export, like `abuseipdb`), `RuleStore` interface, fail-safe + supply-chain rules above, bundled patterns as fallback. Re-check `coraza-node` npm status before building — if a real JS/Workers Coraza exists, a `coraza` adapter beats hand-syncing lists.
