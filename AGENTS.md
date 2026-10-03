# AGENTS.md

Guidance for coding agents working on keyshim. The README describes the
product and its security model; read its "Security model" section before
changing the proxy, storage or UI.

## Commands

Go 1.27.1 or newer (see `go.mod`).

```bash
gofmt -l .                        # must print nothing
go vet ./...
go test -race -count=1 ./...
node --check internal/ui/static/app.js
shellcheck install.sh scripts/*.sh
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
scripts/build-release.sh v0.0.0-dev dist   # local release build; replaces dist/
```

CI (`.github/workflows/ci.yml`) runs all of these: formatting, vet, tests and
the JavaScript check on Linux and macOS, the rest on Linux. Run them before
committing.

## Layout

| Path | Owns |
|---|---|
| `cmd/keyshim` | CLI: `run`, `check`, `ca`, `client`, `secrets`, `key`, `version` |
| `internal/config` | YAML config, defaults, validation, warnings, atomic writes |
| `internal/keystore` | Master key (OS keychain or passphrase), `Seal`/`Open`; `keystoretest` for tests |
| `internal/secrets` | Providers (encrypted local file, Azure Key Vault) and the TTL cache |
| `internal/rules` | Rule compilation, host/path/client matching, header templates |
| `internal/proxy` | Proxy, TLS interception, injection, redaction, client auth, target guard |
| `internal/ca` | Local CA and leaf certificates |
| `internal/app` | Running configuration: apply, reload, clients |
| `internal/audit` | In-memory activity log |
| `internal/ui` | UI server (sessions, API); `static/` is plain HTML/CSS/JS, embedded, no build step |
| `scripts/`, `install.sh`, `.github/` | Release build, installer, CI and release workflows |
| `spikes/` | Historical experiments; not built or tested |

## Security invariants

Changes must keep all of these. Add or update a test when touching one.

- Secret values never appear in logs, error messages, audit events, API
  responses or the UI. Errors name secrets, never their values.
- Secrets are injected only into headers, only over TLS keyshim verifies,
  and only for requests a rule matches (host, port, method, path, client).
- The `Host` header must match the CONNECT target; ambiguous paths never
  match path rules; wildcards cannot cover public suffixes.
- Proxy clients must authenticate (`name:token`); only token hashes are
  stored. The loopback/link-local target guard stays on by default.
- Local secrets and the CA key are only stored sealed, bound to their
  purpose. Local values are create-only: never readable or editable.
- The UI uses bearer sessions from single-use login tokens. No cookies
  (they leak to other ports on 127.0.0.1). Render all data with
  `textContent`/the `h()` helper, never `innerHTML`; request paths in the
  activity log come from untrusted clients. Keep the strict CSP: no inline
  scripts or styles.
- Config and key files written by keyshim are `0600`; files that others can
  write are refused.

## Conventions

- Match the surrounding code: standard library first, small packages, doc
  comments on exported names, comments that explain why.
- New dependencies need a reason. Release builds must stay `CGO_ENABLED=0`
  and reproducible.
- UI changes: check light, dark and a 390 px wide viewport in a browser, with
  no console errors or horizontal overflow.
- Branches: `feature/<short-description>` or `bugfix/<short-description>`
  off `main`. Open draft pull requests; never push to `main`.
- Windows is not supported yet: permission checks rely on Unix file modes.
