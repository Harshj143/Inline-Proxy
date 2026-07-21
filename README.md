# MCP Security Gateway

A transparent security proxy for AI agents. It sits between an MCP client
(the agent host, e.g. Claude Desktop) and an MCP server, and enforces
policy on every tool call in real time:

- **Tool allowlisting (request stage):** blocked tools never reach the
  upstream server. Default deny for anything not in the policy.
- **PII redaction (response stage):** emails, phones, SSNs, credit cards,
  and IPs are stripped from tool results *before* the LLM sees them, so
  sensitive data never enters the model's context window. Arguments the
  agent sends out are scrubbed too.
- **Role-based policy (request stage):** the gateway runs for one caller
  identity (`--role admin`, `--role analyst`), and a tool can be treated
  differently per role. Same `crm.get_customer`: an admin sees raw PII, an
  analyst sees it redacted. No code changes, no second server.
- **Nine-ish action pipeline (request + response stage):** beyond
  allow/block/redact, a rule can **rewrite** the arguments to a safe form
  (force a SQL `LIMIT`, pin `read_only=true`), **quarantine** a result
  (let the call run but withhold the output from the LLM and flag it), or
  **require_approval** — pause and ask a human, proceed only on sign-off.
- **LLM-powered anomaly detection (session stage):** an optional monitor
  (Claude Haiku, or a local heuristic fallback) watches the live tool-call
  trace and judges whether the *shape* of the session looks like an attack —
  recon sprawl, read-secrets-then-exfiltrate — even when no static rule
  fired. A flag feeds the risk engine as extra points.
- **Argument-level constraints (request stage):** an allowed tool can
  still be denied based on WHAT it is doing, e.g. `db.execute_sql`
  restricted to read-only SELECT statements.
- **Per-session risk scoring with auto-suspend:** blocked calls and
  constraint violations add weighted risk points. At 50 the session is
  flagged ELEVATED; at 80 it is SUSPENDED and every further tool call is
  denied, even previously allowed ones. One misbehaving agent cannot keep
  probing.
- **Taint tracking (session stage):** once a session calls a tool that
  ingests untrusted external content (a taint source, e.g. `web.fetch`),
  the session is marked tainted and outbound/mutating tools (taint sinks,
  e.g. `http.post`) are blocked until a human clears it. This breaks the
  "lethal trifecta" without having to detect the prompt injection itself.
- **Sequence-aware policies (request stage):** rules of the form "forbid
  tool B once tool A has run this session" catch attacks that are invisible
  per-call, e.g. no outbound POST after reading customer PII.
- **Full audit trail:** every decision, redaction, and risk score change
  written as JSONL, ready to ship to a SIEM.

The design mirrors, in miniature, the protocol-aware proxy pattern used by
products like Formal: no changes to the agent, no changes to the server,
just point the client at the gateway.

```
agent / MCP client  <-- stdio -->  GATEWAY  <-- stdio -->  real MCP server
                                    |
                          policies.json  audit.log
```

## Quick start (zero dependencies, Python 3.10+)

```bash
python demo/run_demo.py
```

This launches the gateway in front of a mock CRM server and shows:

1. `initialize` and `tools/list` passing through untouched
2. `crm.get_customer` allowed, with all PII redacted from the result
3. `search.docs` allowed untouched
4. `db.execute_sql` blocked by an explicit rule
5. an unknown tool blocked by default deny
6. the full audit trail

### Attack scenario demo

```bash
python demo/attack_scenario.py
```

Plays out a prompt-injection-driven exfiltration and shows the gateway
stopping it:

1. the agent fetches a poisoned web page -> session becomes tainted
2. steered by the hidden instruction, it reads a customer record -> allowed
   but PII is masked in the response
3. it tries to POST the data to an attacker URL -> blocked, by taint and by
   a sequence rule, either of which suffices
4. a separate clean session is still allowed to POST, proving the control
   is conditional on session state, not a blanket ban

The gateway never detects the injection payload. It assumes any session
exposed to untrusted content might be compromised and refuses to let that
session complete the exfiltration.

### Feature demo (roles, extended actions, anomaly detection)

```bash
python demo/feature_demo.py
```

Walks through the three richer controls, each in its own gateway session:

1. `crm.get_customer` as `analyst` (redacted) vs `admin` (raw PII) — one
   tool, two identities
2. `rewrite` capping an unbounded `SELECT *` with `LIMIT 1000`;
   `quarantine` withholding a secret-leaking log tail from the model;
   `require_approval` on `admin.delete_user`, denied then approved
3. the LLM monitor (local heuristic backend) flagging a
   read-then-exfiltrate trace and scoring it into the risk engine

Add `--anomaly claude` on the gateway (with `pip install anthropic` and
`ANTHROPIC_API_KEY` set) to use Claude Haiku for the monitor instead of the
heuristic stand-in.

## Real end-to-end: a real MCP server + the Security Ops Console

Everything above talks to a mock. This runs the gateway in front of
Anthropic's **real** `@modelcontextprotocol/server-filesystem` (real files on
disk), with a real policy ([policies.filesystem.json](policies.filesystem.json)),
and the **Security Ops Console** — a zero-dependency web app that streams every
decision live, charts the risk score over time, lets you filter/search the
feed, lists past sessions for replay, and renders the active policy as a
scannable tool/action table with policy backtesting.

Requires Node/`npx` (for the filesystem server). Two terminals:

```bash
# terminal 1 — the console (stdlib only), tailing the audit log
python dashboard/server.py --audit audit.log --policy policies.filesystem.json
# open http://localhost:8000

# terminal 2 — the gateway + real filesystem server, driven end-to-end
python demo/real_filesystem_demo.py
```

Watch the console: real PII read off disk gets `REDACTED`, `write_file` and
`edit_file` pass through approval, an off-allowlist `delete_file` is blocked,
and the risk chart climbs with a red marker at each block — all against real
files in `./sandbox`.

The filesystem policy is deliberately practical, not a toy:

- reads (`read_text_file`, `read_file`, …) → **redact** PII before the model
- mutations (`write_file`, `edit_file`, `move_file`) → **require_approval**
- listing / search / info → **allow**
- anything else → **default-deny**

### Approve in the browser (human-in-the-loop)

Run the gateway with `--approvals http` and the console becomes the approver:
every `require_approval` call pauses the gateway and pops up in the console
with **Approve / Deny** buttons; your click unblocks the call. The browser is
the human in the loop — no CLI flag deciding for you.

```bash
# terminal 1
python dashboard/server.py --audit audit.log        # http://localhost:8000
# terminal 2 — writes will WAIT for your click in the console
python demo/console_demo.py
```

The console is read-only over enforcement plus this approval relay; all policy
lives in the gateway. Sessions are grouped by id, so the **Sessions** tab lists
every past run with its final risk score — click one to replay its full trace.
The **Policy** tab reads the same policy file and shows default action,
redaction entities, taint/sequence controls, role overrides, constraints,
rewrites, and approval rules. Its **Policy backtesting** panel lets you paste
or edit a candidate policy, replay it against the historical audit log, and see
what would change before you enforce it: newly blocked calls, newly allowed
calls, new redactions, approval changes, and partial-confidence cases where old
logs intentionally did not store raw arguments.

## Wiring it into Claude Desktop / Claude Code (real agent)

Point your MCP client at the gateway instead of the server; the gateway
launches the real server behind it. The agent (Claude) never knows it's there.
**Use absolute paths** — the client won't run from this repo's directory.

```jsonc
{
  "mcpServers": {
    "filesystem": {
      "command": "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3",
      "args": [
        "-m", "gateway.main",
        "--policy", "/ABS/PATH/mcp-security-gateway/policies.filesystem.json",
        "--audit",  "/ABS/PATH/mcp-security-gateway/audit.log",
        "--role",   "analyst",
        "--approvals", "deny",     // fail-closed; writes are blocked pending a human
        "--anomaly",   "heuristic",
        "--", "/usr/local/bin/npx", "-y",
        "@modelcontextprotocol/server-filesystem", "/ABS/PATH/you/want/exposed"
      ],
      "env": { "PYTHONPATH": "/ABS/PATH/mcp-security-gateway" }
    }
  }
}
```

Claude Desktop config lives at
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS).
Notes: use the **full path** to `python3` and `npx` (Desktop's `PATH` is
minimal); set `PYTHONPATH` to the repo so `-m gateway.main` resolves; keep the
dashboard running against the same `--audit` file to watch the real agent's
calls being policed live. Set `--approvals allow` only if you want writes to go
through without a human (a real deployment would wire the broker to Slack).

Any other stdio MCP server works the same way — write a policy for its tool
names and pass its launch command after `--`:

```json
{
  "mcpServers": {
    "crm": {
      "command": "python",
      "args": ["-m", "gateway.main",
               "--policy", "/path/to/policies.json",
               "--audit", "/path/to/audit.log",
               "--role", "analyst",
               "--anomaly", "claude",
               "--", "python", "/path/to/real_server.py"]
    }
  }
}
```

## Policy file

```json
{
  "default_action": "block",
  "tools": {
    "crm.get_customer": {
      "action": "redact",
      "roles": {"admin": {"action": "allow"}, "analyst": {"action": "redact"}}
    },
    "search.docs":      {"action": "allow"},
    "db.execute_sql":   {"action": "rewrite",
                         "rewrites": [{"arg": "sql", "append": " LIMIT 1000",
                                       "unless_match": "\\blimit\\b", "flags": "i"}],
                         "constraints": [{"arg": "sql", "must_match": "^\\s*SELECT\\b",
                                          "flags": "i"}]},
    "logs.tail":        {"action": "quarantine"},
    "admin.delete_user":{"action": "require_approval", "then": "allow"}
  },
  "redact_entities": ["EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IP_ADDRESS"],
  "taint_sources": ["web.fetch"],
  "taint_sinks": ["http.post", "db.execute_sql"],
  "sequence_rules": [
    {"after": "crm.get_customer", "forbid": "http.post",
     "reason": "no outbound POST after reading customer PII"}
  ]
}
```

Actions:

| action | effect |
|---|---|
| `allow` | pass through untouched |
| `block` | deny at the gateway with a JSON-RPC error |
| `redact` | allow, but scrub PII from arguments and results |
| `rewrite` | allow, but first rewrite the arguments (`set` a value, or `append` a string `unless_match` already satisfies it) |
| `quarantine` | run the call upstream, but withhold the result from the LLM and flag it for review |
| `require_approval` | pause and ask a human; on approval fall through to `then` (default `allow`), on denial block |

A `"roles"` map on any tool overrides the fields it names for a given
`--role`, so one tool can behave differently per caller identity.

## Redaction backends

Regex works out of the box. For NER-based detection (names, locations,
higher recall), install Presidio and the gateway picks it up automatically:

```bash
pip install presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_lg
```

## Layout

```
gateway/
  main.py     stdio JSON-RPC proxy, request/response interception
  policy.py   role-aware policy engine (allow/block/redact/rewrite/quarantine/require_approval)
  redact.py   PII redaction (Presidio with regex fallback)
  approval.py human-in-the-loop approval broker (fail-closed)
  anomaly.py  LLM behavioral monitor (Claude Haiku, or local heuristic)
  audit.py    JSONL audit logging
  risk.py     per-session risk scoring, escalation, auto-suspend
  sequence.py taint tracking + sequence-aware policies
dashboard/                Security Ops Console (stdlib http.server + SSE; no deps)
  server.py               control plane: audit stream, approval relay, sessions/policy/backtest API
  index.html styles.css app.js   clean-enterprise single-page UI
demo/
  mock_server.py         PII-leaking mock CRM MCP server
  run_demo.py            end-to-end demonstration
  attack_scenario.py     prompt-injection exfiltration, blocked
  feature_demo.py        roles, extended actions, anomaly detection
  real_filesystem_demo.py  gateway in front of the REAL filesystem MCP server
  console_demo.py        interactive browser-approval flow (real server)
policies.json            demo policy (mock CRM)
policies.filesystem.json policy for the real filesystem MCP server
```

## Known limitations / roadmap

- Newline-delimited stdio transport only; no HTTP/SSE transport yet
- SQL constraints are regex-based; a real parser would resist tricks like
  CTEs wrapping writes (`WITH x AS (DELETE ...) SELECT ...`) and comments
- Risk scores live per-process; a shared store would let scores follow an
  agent identity across sessions
- Regex tier misses unstructured PII like names; Presidio closes most of
  that gap
- Human approval is fail-closed but synchronous and per-process; a real
  deployment would post to Slack/PagerDuty and resume asynchronously
- The LLM anomaly monitor runs on every tool call in the demo; production
  would sample/debounce it and share verdicts across an agent identity
- Prompt injection arriving *through* tool responses is still not parsed;
  taint tracking and the behavioral monitor bound its blast radius without
  detecting the payload itself
