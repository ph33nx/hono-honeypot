# Maintenance

Periodic upkeep for this package. Run every 4-8 weeks. Drift is cheap to fix monthly and expensive
to fix yearly, when you are two majors deep with nothing bisectable.

**Last run: 2026-08-05.**

## Supply-chain cooldown is sacred

`bunfig.toml` sets `minimumReleaseAge = 604800` (7 days). Never bypass it to take a bump.

This package ships **zero runtime dependencies**, so none of this reaches a consumer's
`node_modules`. The window exists because `prepublishOnly` runs the build: a compromised build-time
dependency would be baked into the published `dist/` and installed by every downstream project.
That makes the dev tree a publish-time artifact chain, not a dev convenience.

A `*` beside a version in `bun outdated` means a newer release exists and the cooldown is holding it
back. That is the feature working. Leave it.

## The run

```bash
bun outdated          # a `*` means cooldown is holding it, not that you are behind
bun update            # in-range only (patch + minor)
bun run typecheck
bun test
bun run build         # REQUIRED. see below
```

**`bun run build` is not optional and typecheck does not substitute for it.** The dts step runs a
separate TypeScript program with its own options, so it fails on things `tsc --noEmit` accepts. Both
TypeScript majors below passed typecheck and all tests, and both broke the build. A green typecheck
plus green tests would have shipped a package that cannot be published.

Two commits, in this order: in-range bumps first, proven green, then one major at a time. That way a
bisect has a clean floor.

## Never narrow `peerDependencies.hono`

It is `^4.0.0` and it stays there. `bun update` prints a peer line alongside the dev line and it is
easy to read that as an instruction. Bumping it to the current minor would drop every consumer
still on an earlier Hono 4.x for no benefit: the dev pin is what our tests run against, and the peer
range is a compatibility promise. Verify with `git diff package.json` after any update.

## HOLD: TypeScript stays on 5.x

**Blocked by `tsup`, not by our code.** Verified 2026-08-05 against `tsup@8.5.1`. Our source is clean
on both majors: `tsc --noEmit` passes and all tests pass on 6 and on 7. Only the bundled dts
generator breaks, and it breaks differently on each:

| Version | Failure | Cause |
|---|---|---|
| `typescript@7.0.2` | `TypeError: Cannot read properties of undefined (reading 'useCaseSensitiveFileNames')` | tsup vendors `rollup-plugin-dts@6.1.1`, itself resolved against `typescript@5.7.3`. It reads TypeScript internals that the 7.x native compiler no longer exposes |
| `typescript@6` | `error TS5101: Option 'baseUrl' is deprecated and will stop functioning in TypeScript 7.0` | `tsup/dist/rollup.js` injects `baseUrl: compilerOptions.baseUrl \|\| "."` into its dts program. Our `tsconfig.json` does not set `baseUrl` at all, so this is unfixable from our side |

Do NOT work around either by adding `ignoreDeprecations` to `tsconfig.json`. That silences a
warning about a real deprecation and leaves the 7.x failure untouched, so it buys nothing and hides
the reason for the hold.

**Unhold when** `tsup` ships a dts pipeline built against TypeScript 6 or later (watch its
`rollup-plugin-dts` version), or if the dts generator is swapped for one that tracks TypeScript
releases. Re-test by running the full gate above; nothing in `src/` needs to change.

## Patterns

The attack-pattern list is the product. Two standing rules:

- **Narrow beats broad, and a false positive is worse than a miss.** A pattern match also earns a
  strike, so an over-broad pattern does not merely block one request, it bans the visitor from every
  path. The invisible-character class was the live example: it once covered the whole
  U+2000-U+203F General Punctuation block, which also holds en and em dashes, curly quotes, the
  ellipsis, and the spaces mobile IMEs insert. That blocked a real visitor on a real search path in
  production. It now covers only U+200B-U+200F, U+2028-U+202E and U+FEFF. Do not widen it back.
- **Every pattern needs a test, and a narrowing needs a test on both sides**: one asserting the
  probe is still blocked, one asserting the legitimate neighbour now passes. Sabotage-check it by
  reverting the pattern and confirming the new test actually fails.

## Release

See `README.md` Contributing for the flow. The `Release` workflow is `workflow_dispatch` only, so a
publish is always deliberate:

```bash
gh workflow run release.yml -f version_bump=patch    # or minor / major
gh run watch
```

It installs frozen, runs tests, builds, bumps the version with no tag, publishes to npm with
provenance, then commits and pushes an ANNOTATED tag. Nothing is published without the tests and the
build passing first.

**The tag must stay annotated.** `git push --follow-tags` pushes only annotated tags and silently
drops lightweight ones, so the original `git tag "v$VERSION"` tagged locally, reported success, and
pushed nothing: every release from v1.0.3 through v1.4.0 reached npm with no tag on the repo, which
was backfilled on 2026-08-05. The step now names both refs explicitly (`git push origin main
"v$VERSION"`) and ends with `git ls-remote --exit-code --tags`, so if the tag ever fails to land the
release fails loudly instead of quietly. Do not simplify either line back.
