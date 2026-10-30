---
name: tok
description: Find and use API tokens, passwords and other credentials the user stored in tokd (their personal token store), with a logged reason. Use whenever a task needs a credential for any system (Zabbix, Jira/Confluence, GitLab, Home Assistant, Synology, a database, a customer API...), before asking the user for one, searching .env files, or reading config files for secrets. Also use when the user mentions tok, tokd, or "my tokens".
---

# tok: credentials with a reason

The user keeps credentials in tokd. You can see what exists and use it; every use is logged on the server with your reason, host, directory, command and agent session, and the user audits that log.

## 1. Look before you ask

```bash
tok ls            # table: name, scope, env var, added, last used, flags, description | when to use
tok ls --json     # same, structured; use it to read descriptions fully
```

- `scope` tells you the context: e.g. `home` is personal, `work`/`acme`... are work or a customer. Pick the token whose scope and "when to use" match the task.
- `approval` flag: each use needs the user's confirmation (see 3). `EXPIRED`: don't use, tell the user.
- Not logged in or login expired: ask the user to run `tok login` (it needs their browser). Don't try to work around it.
- Nothing fits: ask the user to add a token in the tokd web app (suggest a name, scope, description and when to use). Don't go hunting through .env files or shell history.

## 2. Use it without seeing it (preferred)

```bash
tok exec --reason "list open Zabbix problems for ACME hosts, user asked why acme-test is red" zabbix-acme -- \
  sh -c 'curl -s -H "Authorization: Bearer $ZABBIX_ACME" https://zabbix.example.com/api_jsonrpc.php -d @req.json'
```

- The token goes into the command's environment as its env var (shown by `tok ls`), or rename it: `NAME=MY_VAR`. Several tokens: list several names.
- Reference the variable inside `sh -c '...'` with single quotes so your shell doesn't expand it first.
- Output is scanned and the value replaced by `[tok:redacted]`.
- Exit code is the command's.

`tok get --reason "..." NAME` prints the raw value, which puts it into your context. Under an agent tok refuses it unless you add `--reveal`, and every reveal needs the user's approval: tok opens the approval page in their browser and waits up to 100 seconds. If it gives up, tell the user to approve in the opened tab and rerun the same command (it reuses the request). The same applies to `tok exec --no-redact`. Add `--reveal` only when the user explicitly asked for the raw value or it must be written somewhere `exec` can't reach (e.g. a config file the user asked you to create), and never echo it into chat.

## 3. Reasons

`--reason` is mandatory (10+ chars) and is what the user reads in the audit log and on approval pages. Make it specific to this task: what you are doing and why this token. Bad: "need token", "testing". Good: "fetch Jira issue PROJ-1234 comments the user asked to summarize".

## 4. Approval-gated tokens

If a token needs approval, tok exits with code 3 and prints a link. Then:

1. Show the user the link as-is in your reply, with one line on what you want to do and why, and stop your turn (or, if you prefer to keep working, run `tok wait <request_id>` with a Bash timeout of 600000 ms; it returns once they decide).
2. After they approve (passkey or password), rerun the exact same command. The approval covers this machine and token for the window they chose (5-60 min), so repeated calls in that window don't ask again.
3. If they deny, don't retry; ask what they want instead.

Never try to approve a request yourself or open the approval page in a browser tool.
