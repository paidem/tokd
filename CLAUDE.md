# tokd

Single-user token store for AI agents: `tokd` server (Go, SQLite, server-rendered web app) and `tok` CLI. See README.md for features and the security model.

## Layout
- `cmd/tokd` server entry, `cmd/tok` client (stdlib only; keep it that way so it cross-compiles everywhere).
- `internal/server`: `db.go` schema + queries, `crypto.go` AES-GCM/mask/codes, `auth.go` password + passkeys + sessions + bearer logins, `api.go` CLI API, `web.go` admin pages, `install.go` /install + /dl, `templates/*.html` (layout.html holds shared blocks), `static/app.js` (passkey ceremonies, confirm forms).
- `skills/tok/SKILL.md` agent skill, also served at /dl/SKILL.md.
- `deploy/tailscale/` compose with a Tailscale sidecar node.

## Work
- Test: `go test ./...` (`internal/server/server_test.go` TestFlow covers setup → login → use → approval; extend it rather than adding new harnesses).
- Run locally: `docker compose up -d --build` → http://localhost:19191 (passkeys work on localhost over http).
- Client binaries: `make dist`. Release: tag `vX.Y.Z` and push; GitHub Actions builds the multi-arch image to ghcr.io and a release with binaries.
- New dependencies only when stdlib can't do it.
- In-memory state (web sessions, pending approvals, grants, device codes) is lost on restart by design.

## Rules
- Public-ready repo: no personal names, hostnames, tailnet names, IPs or employer/customer names in code, docs, tests or commit messages. Use `acme`, `example.com`, `your-tailnet.ts.net`.
