<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/tokd-logo-dark.svg">
    <img src="assets/brand/tokd-logo-light.svg" alt="tokd" height="72">
  </picture>
</h1>

A small, single-user token store for AI agents. You keep API tokens and passwords in one place. Agents can list them and use them, but they must give a reason each time, and every use is logged. Tokens you mark as sensitive need your approval (passkey or password) before each use window.

- **tokd** is the server: Go, SQLite, values encrypted with AES-256-GCM, web app for you.
- **tok** is the client: one static binary for macOS, Linux and Windows.
- **skills/tok/SKILL.md** teaches Claude Code (or any agent that reads skills) how to use it.

## What you get

- Web app: add and edit tokens (name, scope, what it is, when to use, env var, expiry, "needs approval"). The list shows values masked (`abcd••••••••wxyz`, fully hidden under 10 characters), with show and copy buttons. Manage scopes, audit events, see logins and revoke them, manage passkeys.
- Scopes such as `home`, `work`, `acme`. Each token has one scope. Each machine's login is limited to the scopes you tick when approving it.
- `tok login <server>`: a device flow. The CLI prints a link and a code. You approve in the browser with a passkey or password, pick the scopes, and pick the lifetime (default and maximum set on the server).
- `tok ls`: the catalog the agent sees. It shows name, scope, description, when to use, added, last used, approval flag and expiry. It never shows values.
- `tok exec --reason ... NAME -- cmd`: runs `cmd` with the token in an environment variable and masks the value in its output.
- `tok get --reason ... NAME`: prints the value. When tok runs under an AI agent (`AI_AGENT`, `CLAUDECODE`, `CLAUDE_CODE_SESSION_ID` or `CODEX_THREAD_ID` set) it refuses unless `--reveal` is given, so agents use `exec` and the value stays out of their context. A reveal by an agent always needs your approval (passkey or password), for every reveal and for any token, even ones not marked "needs approval"; tok opens the approval page itself. `tok exec --no-redact` under an agent is treated the same way.
- Approval: a gated token makes tok print an approval link and exit 3. You open the link, check the reason, host, directory and command, and confirm with a passkey or password. You then choose 5, 15 or 60 minutes. Within that window the same machine can use the token again without asking.
- Event log: every use, denial, approval, login and change, with the reason, host, login, directory, command and agent session (Claude Code session id, T3 thread id).

## Run it

Images: `ghcr.io/paidem/tokd` (linux/amd64 + arm64). `:latest` and `:X.Y.Z` come from release tags `vX.Y.Z`, `:main` from the main branch. Release tags also publish the `tok` binaries on the GitHub release page.

Local, single machine:

```bash
docker compose up -d --build
open http://localhost:19191      # set the password, then add a passkey in Settings
tok login http://localhost:19191
```

Passkeys work on `http://localhost` because browsers treat localhost as a secure context. Any other host needs HTTPS.

On a server, put it behind HTTPS and set `TOKD_URL` to the exact origin you open in the browser. Passkeys are bound to that host name, so changing it later means registering them again. Some options:

- Tailscale, own node (recommended): `deploy/tailscale/` runs a Tailscale sidecar so tokd is `https://tok.<tailnet>.ts.net`, independent of the host. The name, passkeys and logins survive moving to another host (copy `data/`, `key/`, `ts-state/`). See the comments in its `compose.yaml`.
- Tailscale on the host: `tailscale serve --bg --https=8443 http://127.0.0.1:19191`, then `TOKD_URL=https://<host>.<tailnet>.ts.net:8443`.
- Any reverse proxy with a certificate, reachable only from your own network or VPN. Don't expose it to the internet.

| env | default | |
|---|---|---|
| `TOKD_URL` | `http://localhost:19191` | public origin; used for passkeys, CSRF checks and links |
| `TOKD_ADDR` | `:19191` | listen address |
| `TOKD_DATA` | `./data` (`/data` in the image) | SQLite database |
| `TOKD_DOWNLOADS` | `./dist` (`/downloads` in the image) | client binaries and SKILL.md served at `/dl/` |
| `TOKD_KEY_FILE` | `$TOKD_DATA/master.key` | 32-byte key, created on first start; compose keeps it in a separate volume |
| `TZ` | `UTC` | time zone for the web UI |

Back up both the database and the key. Neither is any use without the other.

## Install the client

From a running tokd (the Docker image bundles `tok` for macOS, Linux and Windows plus the agent skill):

```bash
curl -fsSL https://tok.example.ts.net/install.sh | sh    # tok -> ~/.local/bin, skill -> ~/.claude/skills/tok
tok login https://tok.example.ts.net
```

The `/install` page lists the individual downloads. Installer overrides: `TOK_BIN_DIR`, `TOK_SKILL_DIR`. An existing skill symlink is left untouched.

From source: `make dist` builds every platform into `dist/` (what tokd serves at `/dl/` when run outside Docker), or `go build -o ~/.local/bin/tok ./cmd/tok`.

The config is stored in `~/.config/tok/config.json` (`%AppData%\tok\config.json` on Windows), mode 0600. Override the path with `TOK_CONFIG`.

## Security model

- Single user. The password is bcrypt-hashed and only a fallback. Passkeys are preferred. Failed attempts slow down exponentially after 5 tries in 15 minutes.
- A machine login is a bearer token, stored hashed on the server. Anything running as you on that machine can use your tokens within the login's scopes until it expires or you revoke it. That is the design. The controls are: a short login lifetime, scopes, the mandatory reason, the audit log and per-token approval.
- An approval needs a fresh passkey or password check. An agent on the same machine can't approve its own request.
- Web sessions, pending approvals and approval windows live in memory. A server restart clears them, and you approve again.
- Values are encrypted at rest. The key file sits next to the database unless you move it (`TOKD_KEY_FILE`), so encryption only protects backups or copies of the database made without the key.
- Output masking in `tok exec` is a convenience. A command can still leak a value in a transformed form (base64, a file it writes, and so on).
