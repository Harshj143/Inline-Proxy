# slack connector

Security pack for **Slack's first-party MCP server** (`https://mcp.slack.com/mcp`).

> **⚠️ Not production-ready yet.** Two things must be settled before this pack
> can be trusted against a live workspace: the tool identifiers are unverified,
> and the gateway cannot currently reach a remote upstream. Both are described
> below under [Verifying the inventory](#verifying-the-inventory) and
> [Deploying this pack](#deploying-this-pack). Everything else — the threat
> model, the controls, the role matrix, the goldens — is complete and testable
> today.

## Why Slack is a hard target

Most connector packs guard a system where sensitivity is a property of the
*tool*: a database read is sensitive, a health check is not. Slack breaks that
assumption. It is where humans paste things — an API key in an `#incidents`
thread, a `.env` in a DM, a customer CSV in a canvas. The same
`read_channel` call is harmless in `#random` and catastrophic in `#payroll`,
and the gateway cannot tell which from the tool name alone.

Two consequences shape this pack:

1. **Content inspection carries most of the weight.** Redaction runs on nearly
   every read, because tool identity is a weak predictor of sensitivity.
2. **Every read is untrusted input.** Anyone — including an external Slack
   Connect user or a stranger in a public channel — can plant text that an
   agent will read as instruction. Slack is a prompt-injection delivery
   mechanism with an enterprise SSO login.

## Threat model

The attack this pack exists to stop, end to end:

1. An attacker posts a message containing hidden instructions into any channel
   the agent can read — or DMs the bot directly, or edits their own Slack
   profile's custom fields.
2. An agent reads it while doing something innocuous ("summarize today's
   standup").
3. The injected text steers the agent to gather sensitive material —
   `search_messages` for `password`, `read_file` on an attachment.
4. The agent sends it somewhere the attacker controls: a DM, a new Connect
   conversation, a canvas.

Step 4 is the only step the gateway can reliably stop, and it stops it without
ever detecting the injection itself. **A session may read untrusted content or
send messages — never both.**

| Capability | Exposure | Control |
|---|---|---|
| **Reads** — messages, threads, files, canvases | Credentials and PII pasted by humans; free-form text that may carry injected instructions | `redact` (strict profile) on conversational text; `quarantine` on files; channel ACL on the named-channel reads |
| **Reads** — user directory and profiles | Email, phone, and attacker-controllable custom fields | `redact` (standard); `reversible` for support agents so a human can recover a contact through an audited detokenize |
| **Reads** — channel and emoji metadata | Reconnaissance value only | `allow` |
| **Writes** — messages, DMs, canvases | Exfiltration; a poisoned runbook that attacks the next reader | `require_approval` (a human sees the content leaving); blocked outright for headless `bot` callers |
| **Destructive** | — | **Nothing to block.** Slack's documented capability set has no delete, archive, or deactivate tool. A future one lands under default-deny automatically. |
| **Taint** | The lethal trifecta: private data + untrusted content + egress | Every content read is a source; every write is a sink; `sequence_rules` restate the read→send paths explicitly |

Everything not named in `policy.yaml` is denied — `default_action: block`.

## Rules

### Allowed outright

`search_channels`, `search_emoji`, `list_channel_members`, `add_reaction`.

Metadata and reactions. Channel names are useful reconnaissance, but blocking
discovery costs far more than it buys: an agent that cannot find a channel
cannot do anything, and the sensitive part — contents — is guarded separately.
`add_reaction` is a covert channel in theory, at a few bits per message; too
low-bandwidth to be worth the usability cost of blocking.

### Redacted

`search_users`, `fetch_user_info` use the `standard` profile — validated PII
regexes plus secret detection.

`read_channel`, `read_thread`, `search_messages`, `read_canvas` use `strict`,
which opportunistically adds Presidio NER when the `[presidio]` extra is
installed and degrades cleanly to the regex tier when it is not. Conversational
text is exactly where NER earns its latency budget: the names and locations no
regex catches.

### Quarantined

`read_file`. File content is opaque and arbitrary — a keystore, a customer CSV,
a `.env`. Unlike conversational text there is no useful partial view, so the
result is withheld from the model and flagged for a human rather than redacted
and passed through. This is the one place the pack chooses a stronger action
than redaction, and it is because redaction's premise — that scrubbing leaves
something safe and useful behind — does not hold for arbitrary binary content.

### Approval-gated

`send_message`, `draft_message`, `create_conversation`, `create_canvas`,
`update_canvas`.

Every one is an egress point. Approval is asked **last** in the pipeline, after
policy, constraints, and the sequence gate — so an approver is never paged
about a call taint rules would have blocked anyway. That ordering is what makes
approvals usable rather than a source of alert fatigue, and
`policy_tests.yaml` pins it: posting to `#exec` dies at the *constraints*
stage, so no human is ever given the chance to wave it through.

`draft_message` is gated despite being documented as preview-only, because
whether a draft can be delivered without a second human action is not
verifiable from Slack's public documentation. Treated as a sink until proven
otherwise; `overrides.example.yaml` shows the downgrade once you have confirmed
it in your own workspace.

### The channel ACL, and its honest limits

`read_channel`, `read_thread`, and `send_message` carry a denylist constraint
matching `exec`, `hr`, `legal`, `board`, `payroll`, `security`, `incident` and
their `-` prefixed forms.

It has **two real gaps**, both pinned by tests rather than buried:

- **Slack addresses channels by opaque ID** (`C0EXEC0001`), and no name pattern
  can see through an ID. `policy_tests.yaml` contains a deliberately-passing
  test named `KNOWN GAP` that documents this. Every deployment should close it
  by listing real IDs in an override — see `overrides.example.yaml` §1.
- **`search_messages` cannot be constrained at all.** It takes a query, not a
  channel, so it reaches across every conversation the OAuth token can see —
  including the channels the ACL denies by name. A channel ACL that only guards
  `read_channel` is trivially bypassed through search.

This is why redaction, not the ACL, is the *primary* control on reads: an
unconfigured pack still strips credentials and PII out of `#exec`. The ACL is
defence in depth, and it is only as good as the IDs you give it.

### Roles

`roles.yaml` overlays three roles, chosen by what the caller can be trusted
with rather than by job title:

- **`workspace-admin`** — sees the raw user directory and raw profiles (they
  already have that access in Slack's own UI; redacting it buys nothing), and
  reads file content redacted instead of quarantined. **Still cannot read
  `#exec`**: a role overlay that does not name `constraints` leaves them in
  place, and a golden asserts that privilege escalation through a role overlay
  does not happen.
- **`support-agent`** — gets `reversible` redaction on user lookups. Contact
  details are tokenized rather than masked, so a human can resolve a token via
  `mcp-gateway detokenize` — audited and principal-attributed. Correlation
  without exposure.
- **`bot`** — headless. All writes are `block`, not `require_approval`.
  Approval would fail closed anyway with nobody to answer, but blocking is
  better: a blocked tool is hidden from `tools/list` entirely, so the model
  never spends a turn attempting a call that cannot succeed.

## Verifying the inventory

**The tool identifiers in this pack are provisional.** Slack documents this
server's capabilities in prose — "Search messages & files", "Send message",
"Read channel" — not as `tools/call` identifiers, and the server is not listed
in the MCP registry. The names here are derived from Slack's own capability
table and **must be reconciled against a live `tools/list`** before the pack is
trusted.

The failure direction is safe: `default_action: block` means a name that is
wrong simply never matches, and the real tool is denied. The pack becomes
inert, not permissive. But inert is not protection.

Two constraints follow from provisional names, and this pack obeys both:

| Form | Behavior on a wrong/absent argument name | Verdict |
|---|---|---|
| `must_not_match` | checked against `""`, no match, passes | **safe** — the only argument control shipped |
| `must_match` | checked against `""`, fails, denies every call | avoid — makes the tool unusable |
| `rewrites` (`set`) | **adds** the argument, injecting an undeclared parameter upstream | avoid — actively breaks calls |

That last row is why this pack ships no result-size caps, which would otherwise
be an obvious win for both blast radius and redaction cost.

### To verify

1. Connect any MCP client to `https://mcp.slack.com/mcp` with a
   directory-published or internal Slack app and capture `tools/list`.
2. Reconcile every identifier and argument name in `tools.yaml`,
   `policy.yaml`, and `roles.yaml`.
3. Add the result caps and any `must_match` allowlists that were unsafe to
   write blind.
4. Record the server version in `manifest.yaml` under `tested_versions`, which
   is deliberately empty until this is done.
5. Re-run the goldens.

## Deploying this pack

**The gateway cannot currently reach a remote MCP server.**
`transports/upstream.py` implements `SubprocessUpstream` only, so both `wrap`
and `serve` expect to *launch* the upstream as a child process. Slack's server
is remote-only, over Streamable HTTP, behind confidential OAuth 2.0 — a flow
the gateway has no way to perform.

The `launch:` template in `manifest.yaml` works around this by running a
stdio↔HTTP bridge as the child process, which also owns the OAuth flow:

```bash
mcp-gateway wrap --connector slack --approvals http -- npx -y mcp-remote https://mcp.slack.com/mcp
```

A native HTTP upstream is the cleaner answer. That is **framework work, not
pack work** — a new `Upstream` implementation plus OAuth token handling — and
should be raised as its own issue rather than solved inside a connector.

## Testing

```bash
mcp-gateway policy validate connectors/slack/policy.yaml connectors/slack/roles.yaml
```

```bash
mcp-gateway policy test --policy connectors/slack/policy.yaml --policy connectors/slack/roles.yaml --tests connectors/slack/policy_tests.yaml
```

Both run in CI: goldens via `tests/unit/test_goldens.py`, and the taint and
sequence model — which the golden harness cannot reach, since it does not run
the sequence gate — via `tests/unit/test_slack_sequence.py`, asserted directly
against the shipped policy file.

## Overriding without forking

A deployment customizes this pack by layering its own file on top — no fork:

```bash
mcp-gateway wrap --connector slack --override my-company.yaml -- <server cmd>
```

Later layers win (field-level merge), so `my-company.yaml` can tighten or relax
individual rules while inheriting everything else. See
`overrides.example.yaml` for worked examples of the four overrides most
deployments need.

**One exception you should know about.** `taint_sources`, `taint_sinks`, and
`sequence_rules` merge as a *union* across layers — additive only, with no
top-level `replace`. An override layer can add a taint source but can never
remove one, so the pack's taint model cannot be narrowed without copying
`policy.yaml` and running it with `--policy` instead of `--connector`. That is
a framework limitation rather than a property of this pack, and it bites here
because the taint model is exactly where deployments will most want to
negotiate. `overrides.example.yaml` §5 documents the workaround.

## Residual risks

Stated plainly, because a threat model that only lists wins is marketing:

- **`search_messages` is the soft spot.** It bypasses the channel ACL by
  design, and it is the single most valuable tool to an attacker. The pack
  redacts it and taints on it; a workspace with genuinely sensitive private
  channels should escalate it to `require_approval` (`overrides.example.yaml`
  §2).
- **Redaction is not exhaustive.** It catches validated PII, known secret
  shapes, high-entropy strings, and — with the `[presidio]` extra — names and
  locations. It does not catch a sentence that is sensitive because of what it
  means. "We are acquiring Initech on Tuesday" survives every detector in the
  engine.
- **The read-or-write taint model is strict.** It deliberately breaks
  "summarize this thread and post the summary", the most common Slack agent
  workflow. That is the correct default for a security pack, but expect
  pressure to relax it, and see the note above about why relaxing it is harder
  than it should be.
- **Approval quality is a human problem.** `require_approval` puts a person in
  front of every outbound message. It is only a control if that person reads
  what they are approving.
