# GitHub connector

Security pack for the official [GitHub MCP server](https://github.com/github/github-mcp-server)
(`ghcr.io/github/github-mcp-server`), validated against **v1.7.0**.

Covers the **entire 109-tool surface** — every tool the server exposes has an
explicit rule. Nothing relies on default-deny by accident, and CI
(`tests/unit/test_github_pack.py`) fails if a tool ever falls through.

```bash
mcp-gateway wrap --connector github -- \
  docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server
```

## The surface

| Toolset | Tools | read | write | destructive | secret-adjacent |
|---|---:|---:|---:|---:|---:|
| actions | 4 | 2 | 1 | 0 | 1 |
| codequality | 1 | 0 | 0 | 0 | 1 |
| codesecurity | 2 | 0 | 0 | 0 | 2 |
| context | 4 | 4 | 0 | 0 | 0 |
| copilot | 2 | 0 | 2 | 0 | 0 |
| copilotissueintents | 1 | 0 | 1 | 0 | 0 |
| dependabot | 2 | 0 | 0 | 0 | 2 |
| discussions | 5 | 4 | 1 | 0 | 0 |
| gists | 4 | 2 | 2 | 0 | 0 |
| git | 1 | 1 | 0 | 0 | 0 |
| issues | 24 | 8 | 16 | 0 | 0 |
| notifications | 6 | 2 | 4 | 0 | 0 |
| orgs | 1 | 1 | 0 | 0 | 0 |
| projects | 3 | 2 | 1 | 0 | 0 |
| pullrequests | 19 | 3 | 15 | 1 | 0 |
| repos | 20 | 14 | 5 | 1 | 0 |
| secretprotection | 2 | 0 | 0 | 0 | 2 |
| securityadvisories | 4 | 4 | 0 | 0 | 0 |
| stargazers | 3 | 1 | 2 | 0 | 0 |
| users | 1 | 1 | 0 | 0 | 0 |
| **Total** | **109** | **49** | **50** | **2** | **8** |

`read`/`write` come from each tool's own `ReadOnlyHint` in the upstream source;
`destructive` and `secret_adjacent` are this pack's security judgment. The full
per-tool inventory is `tools.yaml`.

## Threat model

An agent with a GitHub token is a powerful, *impersonatable* identity. Three
things make GitHub particularly dangerous as an MCP surface:

1. **Most GitHub text is attacker-authored.** Anyone can open an issue, comment
   on a PR, or push a branch to a fork. The moment an agent reads that text, the
   agent's instructions are potentially attacker-controlled — this is prompt
   injection with a real write-capable identity attached.
2. **CI output leaks secrets.** Actions logs routinely contain tokens, and
   secret-scanning results contain the detected secret *by definition*.
3. **GitHub is its own exfiltration channel.** A public gist, a pushed file, or a
   comment body will happily carry stolen data out — no external network needed,
   so a network egress policy does not save you.

### Reads → `redact` (49 tools)

Every read is scrubbed before the model sees it (`redaction: standard`), because
repository content, issue bodies, and commit messages routinely carry both PII
and credentials. Reads are permitted because an agent that cannot read is
useless — the defense is scrubbing plus the taint marking below, not refusal.

### Secret-adjacent reads → `quarantine` / strict `redact` (8 tools)

| Tools | Action | Why |
|---|---|---|
| `get_job_logs`, `list_secret_scanning_alerts`, `get_secret_scanning_alert` | `quarantine` | These *are* secret material. The call runs and is audited, but the result is withheld from the model and flagged for a human. Redaction is not enough when the payload's whole purpose is to contain the secret. |
| `list_code_scanning_alerts`, `get_code_scanning_alert`, `get_dependabot_alert`, `list_dependabot_alerts`, `get_code_quality_finding` | `redact: strict` | Genuinely useful to an agent triaging vulnerabilities, but findings quote vulnerable code and often credentials — so the strictest profile applies. |

### Writes → `require_approval` (50 tools)

Every state-changing call asks a human first (`then: allow` — approval runs the
real action on approval). With no approver wired, `require_approval` **fails
closed**, so an unattended deployment cannot write to GitHub at all. That covers
issue/PR creation and edits, comments, reviews, labels, assignees, merges,
branches, pushes, gists, stars, notifications, Copilot assignment, and CI
triggers.

Approval is deliberately *not* reserved for "dangerous-looking" writes: a comment
body is an exfiltration channel, and an innocuous-looking label change is how an
attacker pivots an automated workflow.

### Destructive → `block` (2 tools)

`delete_file` and `delete_pending_pull_request_review` cause irreversible loss
and are blocked outright — **for every role, including `release-manager`**
(enforced by a test). A human who genuinely needs to delete something can use
GitHub directly; an agent has no business doing it.

### Taint & exfiltration guards

- **Sources** (14): the free-form, attacker-influenceable reads — `issue_read`,
  `list_issues`, `search_issues`, discussions, PR reads, `get_file_contents`,
  gists, `search_code`, `get_notification_details`. Reading any of these marks
  the session tainted.
- **Sinks** (4): `create_gist`, `update_gist`, `push_files`,
  `create_or_update_file` — the tools that can carry data out. Once a session is
  tainted these are **blocked**, on top of their approval gate.
- **Sequence rules**: a `create_gist` immediately after `get_job_logs` or
  `list_secret_scanning_alerts` is blocked as a read-then-exfiltrate pattern.

The attack this stops end-to-end: *poisoned issue → agent reads it (tainted) →
agent tries to push the repo's `.env` to a gist → blocked.*

## Roles (`roles.yaml`)

Overlays layered after `policy.yaml`; field-level merge, so a relaxed action
still inherits the base rule's redaction and reason.

| Role | Effect |
|---|---|
| *(none)* / `developer` | The default: reads redacted, all writes approval-gated. |
| `reviewer` | Comment/review/reaction writes become `allow` (high-volume, low blast radius). **Cannot merge** — that still needs approval. |
| `release-manager` | `merge_pull_request`, `create_branch`, `push_files`, `create_or_update_file`, `update_pull_request_branch`, `actions_run_trigger` become `allow`. Still cannot delete. |
| `bot` | Unattended: every write is `block`, not `require_approval` — no human exists to answer the prompt, so blocking outright is honest instead of a guaranteed timeout. Reads still work (redacted). |

```bash
mcp-gateway wrap --connector github --role reviewer -- <server cmd>
```

## Overriding without forking

Layer your own policy file on top — later layers win, field by field:

```bash
mcp-gateway wrap --connector github --override my-company.yaml -- <server cmd>
```

```yaml
# my-company.yaml — tighten and relax without touching the pack
schema_version: 1
tools:
  create_gist:
    action: block            # we never allow gists, approved or not
    reason: "company policy: no gists from agents"
  add_issue_comment:
    action: allow            # we accept the risk for comments
    reason: "triage bot posts comments freely"
```

## Upgrading the upstream server

`tools.yaml` is pinned to the version in `manifest.yaml`. On a version bump:

1. Re-extract the inventory from the new tag's `pkg/github/*.go`.
2. `test_inventory_is_the_full_surface` fails on a changed tool count — that is
   the prompt to review, not a bug.
3. Classify each new tool, add its rule, extend `policy_tests.yaml`.

Until then, any tool the pack has not seen hits `default_action: block` — new
upstream capability is denied by default rather than silently allowed.

## Verify

```bash
mcp-gateway policy test --policy connectors/github/policy.yaml \
                        --policy connectors/github/roles.yaml \
                        --tests  connectors/github/policy_tests.yaml
PYTHONPATH=src python3 -m pytest tests/unit/test_github_pack.py -q
```
