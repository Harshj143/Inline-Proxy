# Slack connector pack

A default-deny security bundle for the **Slack** MCP server
[`korotovsky/slack-mcp-server`](https://github.com/korotovsky/slack-mcp-server) —
all **22** tools, every one carrying an explicit rule, extracted from source.

## Why this server, not Slack's first-party endpoint

Slack ships a first-party hosted MCP server at `mcp.slack.com`. This pack does
**not** target it, on purpose: Slack documents that server's capabilities in
prose ("send a message", "read a channel") and never publishes the `tools/call`
identifiers a policy has to match. You cannot write a verifiable, complete
default-deny policy against tool names you cannot see — the surface is
unknowable from the outside, so an earlier iteration of this pack that targeted
it was permanently stuck at "provisional, unverified."

`korotovsky/slack-mcp-server` is the most powerful open-source Slack MCP server
and its tool surface is **extractable from source** (`pkg/server/server.go`),
exactly like the GitHub pack extracts from `github-mcp-server`. That makes the
inventory here complete and *verified*: all 22 tool names are real, and
`tools/extract_inventory.py` re-derives them on an upstream bump. Completeness
you can check beats a first-party badge you can't.

## Why Slack is a hard target

Most connector packs guard a system where sensitivity is a property of the
*tool*: a database read is sensitive, a health check is not. Slack breaks that
assumption. It is where humans paste things — an API key in an `#incidents`
thread, a `.env` in a DM, a customer CSV in a saved item. The same
`conversations_history` call is harmless in `#random` and catastrophic in
`#payroll`, and the gateway cannot tell which from the tool name alone.

Two consequences shape this pack:

1. **Content inspection carries most of the weight.** Redaction runs on every
   read, because tool identity is a weak predictor of sensitivity — and message
   text gets the **strict** profile, not standard.
2. **Every content read is untrusted input.** Anyone — including an external
   Slack Connect user or a stranger in a public channel — can plant text an agent
   reads as instruction. Slack is a prompt-injection delivery mechanism with an
   enterprise SSO login. So every content read is a **taint source**, and the
   send path is blocked once the session has ingested any of it.

## The policy at a glance

| Class | Tools | Action | Why |
|---|---|---|---|
| secret_adjacent (message/file text) | 5 | `redact` (`strict`) | `conversations_history` / `_replies` / `_search_messages` / `_unreads` / `saved_list` — where secrets get pasted; strict scrub keeps a usable view |
| secret_adjacent (opaque bytes) | 1 | `quarantine` | `attachment_get_data` returns file bytes — a keystore, a `.env` — with no useful partial view |
| read (metadata) | 4 | `redact` (`standard`) | `users_search` (PII), `channels_list`, `channels_me`, `usergroups_list` |
| write | 12 | `require_approval` → allow | every state change is gated on a human (fail-closed with no approver) |
| destructive | 0 | — | this server exposes **no** delete/archive tool; nothing to block |

**No destructive rules ship because there is nothing to block** — the server has
no message deletion, no channel archival, no user deactivation. If a future
version adds one, it lands under default-deny automatically, which is the correct
default. `test_slack_pack.py::test_no_destructive_tools_exist` pins the claim.

Four write/read tools (`conversations_add_message`, `reactions_add`,
`reactions_remove`, `attachment_get_data`) are gated **off by default** in the
upstream itself, behind env flags. They are inventoried and ruled anyway, so the
gateway already has a policy in place the moment an operator turns them on.

### Taint model

- **7 taint sources** — every content read: the four `conversations_*` reads,
  `saved_list`, `attachment_get_data`, and `users_search` (Slack profile custom
  fields are attacker-controllable in any shared/Connect workspace).
- **3 taint sinks** — `conversations_add_message` (the primary exfiltration path:
  a DM to an attacker-controlled account leaves the workspace instantly and is
  invisible to channel-level monitoring), plus `usergroups_create` /
  `usergroups_update` (their name/handle/description are free-text fields that
  persist).
- Once a session has read untrusted content, **the send path is blocked**. Three
  `sequence_rules` additionally restate the sharpest read→send pairs (channel
  read, workspace search, attachment download → send) so the guard survives a
  future edit that narrows `taint_sources` — proven by
  `test_slack_sequence.py` against an *untainted* session.

### Roles (`roles.yaml`, layered after `policy.yaml`)

| Role | Grant |
|---|---|
| _default_ | every write needs approval |
| `support-agent` | messaging and read-state are their normal work: send, react, mark, join/leave, saved-item updates are un-gated; user-group administration still needs approval |
| `workspace-admin` | every write un-gated (they run the workspace) |
| `bot` | unattended: no human can answer an approval prompt, so **every write is blocked** outright |

**Taint still applies on top of a role grant.** Even for `support-agent`, whose
send is un-gated, a session that has read untrusted content is blocked from
`conversations_add_message` by the sequence gate — the role relaxes the *static*
decision, not the session-state control.

## Deploying this pack

```bash
# Sidecar in front of the real server (a Slack token in the environment):
mcp-gateway wrap --connector slack -- \
  docker run -i --rm -e SLACK_MCP_XOXP_TOKEN \
    ghcr.io/korotovsky/slack-mcp-server mcp-server --transport stdio

# Attach a role:
mcp-gateway wrap --connector slack --role support-agent -- <server cmd>
```

Customize without forking, by layering an override on top — see
[`overrides.example.yaml`](overrides.example.yaml) for a channel-ID ACL, a
tightened `conversations_search_messages`, and the (framework-limited) taint
relaxation:

```bash
mcp-gateway wrap --connector slack --override my-company.yaml -- <server cmd>
```

## Verifying / upgrading the inventory

`tools.yaml` is generated from upstream source, not hand-listed:

```bash
git clone --depth 1 https://github.com/korotovsky/slack-mcp-server.git /tmp/slack
python3 connectors/slack/tools/extract_inventory.py /tmp/slack /tmp/slack.json
```

On an upstream bump: re-run the extract, classify anything new, add its rule to
`policy.yaml`, extend `policy_tests.yaml`, and bump `tested_versions` in
`manifest.yaml`. `tests/unit/test_slack_pack.py::test_inventory_is_the_full_surface`
guards the count (22), so a surface change fails CI until the pack is re-reviewed.

## Known limitation

- **Channel ACL needs your channel IDs.** korotovsky addresses channels by opaque
  ID, so a name-based denylist cannot see through an ID. The shipped policy leans
  on redaction + taint rather than a channel ACL; `overrides.example.yaml` shows
  how to add an ID-based `must_not_match` for the channels an agent must never
  read. A per-connector constraint plugin (the cleaner home for this) is deferred
  framework work — see docs/PLAN.md Phase 6a.
