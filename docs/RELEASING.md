# Releasing agent-witness-protocol

Publishing is **deliberate**: only a published GitHub Release triggers
[`.github/workflows/release.yml`](../.github/workflows/release.yml). Pushes to
`main` run CI only — they never publish to npm.

## Prerequisites

1. **`NPM_TOKEN` repo secret** on [RBKunnela/awp](https://github.com/RBKunnela/awp)
   - npm **Automation** (or granular) token with **publish** rights to
     `agent-witness-protocol`
   - **Copy from paybot-sdk:** the same token is already set on
     `RBKunnela/paybot-sdk` as `NPM_TOKEN`. GitHub does not allow reading secret
     values via CLI — an operator must copy the token from the npm dashboard
     (or wherever it was stored when paybot-sdk was set up) into:
     **Settings → Secrets and variables → Actions → New repository secret**
     → name `NPM_TOKEN`
   - CLI (if you have the token in the shell):  
     `gh secret set NPM_TOKEN -R RBKunnela/awp --body "$env:NPM_TOKEN"`  
     (PowerShell) or `gh secret set NPM_TOKEN -R RBKunnela/awp` (stdin)
2. `package.json` `version` bumped and committed on `main`
3. `CHANGELOG.md` updated for the version (recommended)

## Cut a release

1. Land version + changelog on `main` (green CI).
2. Tag matching `package.json` (leading `v` is stripped for the version check):

   ```bash
   git checkout main
   git pull
   # ensure package.json version is e.g. 0.2.1
   git tag -a v0.2.1 -m "v0.2.1"
   git push origin v0.2.1
   ```

3. Create a GitHub Release for that tag (UI or CLI):

   ```bash
   gh release create v0.2.1 --title "v0.2.1" --notes-file CHANGELOG.md
   # prerelease (publishes npm dist-tag `next`, not `latest`):
   # gh release create v0.2.1-rc.1 --prerelease --title "v0.2.1-rc.1"
   ```

4. Watch **Actions → Release**. The job will:
   - Fail if the tag (without `v`) ≠ `package.json` version
   - `npm ci` → build → test
   - Skip publish if that version is already on npm
   - Otherwise `npm publish --access public` with `NODE_AUTH_TOKEN` /
     `secrets.NPM_TOKEN`, optional `--provenance` (OIDC `id-token: write`)

## Troubleshooting

| Symptom | Likely fix |
|--------|------------|
| Tag/version mismatch | Align `package.json` version with tag (e.g. tag `v0.2.1` ↔ `"version": "0.2.1"`) |
| 401 / 404 on publish | Set or rotate `NPM_TOKEN`; ensure token can publish this package name |
| Provenance / OIDC error | Remove `--provenance` from the publish step in `release.yml` and re-run |
| Version already published | Expected skip — bump version for a new release |

## See also

- Package: https://www.npmjs.com/package/agent-witness-protocol
- Mirror workflow pattern: `RBKunnela/paybot-sdk` `.github/workflows/release.yml`
