# Contributing to AWP

Thanks for helping improve the Agent Witness Protocol.

## Development setup

Requirements: **Node.js ≥ 18** (CI uses Node 20).

```bash
npm ci
npm run build
npm test
```

Useful scripts:

| Script | Purpose |
|--------|---------|
| `npm run lint` | ESLint on TypeScript sources |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run build` | Emit `dist/` |
| `npm test` | Vitest suite (must stay green) |
| `npm run test:coverage` | Coverage report |

## Pull requests

1. Fork / branch from `main`.
2. Keep changes focused; prefer small PRs.
3. Ensure **lint, typecheck, build, and tests** pass locally (same as CI).
4. Do not commit secrets, production keys, or large media (`docs/videos/`, `*.mp4` — videos live on YouTube).
5. Do not weaken tests to go green; fix the product or the fixture.

CI (`.github/workflows/ci.yml`) runs on every push/PR to `main`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new capability
- `fix:` bug fix
- `docs:` documentation only
- `test:` tests only
- `chore:` tooling / metadata
- `refactor:` no behavior change

Examples: `feat(verify): surface honesty footer on PASS`, `docs: clarify integrity-since-witness`.

## Honesty boundary (non-negotiable)

AWP must not overclaim. Contributions that present verification as:

- authenticity at origin,
- completeness of all agent actions, or
- proof of legal identity

will be rejected. PASS means **integrity-since-witness** via best-effort cryptographic re-performance — see `SECURITY.md`.

The `https://awp.dev` namespace is a **format id**, not endorsement of emitters.

## Scope tips

- Wire-format / namespace changes are high impact; coordinate before changing `predicateType` or schema `$id`.
- Prefer reusing existing envelope, log, and verify paths over new crypto primitives.
- Sample receipts and fixtures must use **test keys only**.

## License

By contributing, you agree that your contributions are licensed under the same terms as the project (Apache-2.0 for code; see `NOTICE` and `LICENSE`).
