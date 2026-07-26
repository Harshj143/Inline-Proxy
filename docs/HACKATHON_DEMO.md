# Hackathon demo runbook

This is the stage-ready demonstration for the Jac implementation of the MCP
Security Gateway. It runs two multi-step attacks through a real MCP
newline-delimited JSON-RPC wrapper. The mock GitHub and Slack servers are
deterministic and local, so the demo needs no tokens, network access, or live
customer data.

## What the judges should understand

The gateway is a firewall and DLP boundary for AI tool use:

```text
AI agent -> Jac MCP gateway -> GitHub or Slack MCP server
              |
              +-> policy, taint, sequence, risk, DLP, audit
```

Every `tools/call` becomes a Jac `CallWalker`. It traverses the graph:

```text
SessionGate -> PolicyMatch -> ConstraintGate -> SequenceGate -> ActionStage
```

The first denial calls `disengage`, so the upstream tool is never executed.
Responses travel back through redaction or quarantine before the model sees
them. Session nodes retain taint, history, and risk across calls.

## One-time setup

Use Python 3.12 or 3.13 and Jac 0.16.7:

```powershell
python -m pip install "jaclang==0.16.7"
Set-Location .\jac
jac install
```

Verify the build:

```powershell
jac check gateway\context.jac gateway\policy.jac gateway\redaction.jac gateway\audit.jac gateway\pipeline.jac transports\wrap.jac
jac test -d tests
```

The suite contains 17 Jac golden tests: nine core engine tests and eight
GitHub/Slack attack tests.

## Stage command

Start the visual Attack Lab from the repository root:

```powershell
.\dashboard\run_attack_lab.ps1
```

Open `http://localhost:8123`. The first screen is a nontechnical, interactive
replay of both attacks. It includes:

- an animated AI agent → Jac gateway → MCP service path;
- a clickable or autoplay attack lifecycle;
- the exact Jac graph gate and policy invoked at each step;
- plain-language “what happened” and “why this matters” explanations;
- live risk, taint, decision, and upstream-delivery state;
- before/after DLP and rewrite examples;
- proof that blocked calls did not reach GitHub or Slack.

The existing Live Ops, Sessions, Policy, approvals, and backtesting views remain
available in the same navigation.

Run the terminal evidence demo in a second window:

```powershell
.\jac\run_demo.ps1 -Scenario all -Pause
```

At the end, the terminal prints a `DASHBOARD BUNDLE` path. To replay the real
Jac audit in the Live Ops and Sessions views, restart the Attack Lab with that
path:

```powershell
.\dashboard\run_attack_lab.ps1 -Audit "jac\demo_output\<timestamp>\attack-lifecycle.audit.jsonl"
```

`-Pause` waits for Enter between controls. Omit it for an automatic run that
finishes in roughly 10–20 seconds.

Individual rehearsals:

```powershell
.\jac\run_demo.ps1 -Scenario github
.\jac\run_demo.ps1 -Scenario slack
```

If Jac is installed in a nonstandard environment, set `JAC_BIN` to the full
path of `jac.exe`.

## Scenario 1 — high: GitHub supply-chain compromise

### Attack

An external contributor places a hidden instruction in a pull request. It
orders the agent to read CI logs, steal deployment credentials, modify a
workflow directly on `main`, execute that workflow, and publish a release.
This combines prompt injection, secret discovery, source mutation, CI
execution, and software supply-chain compromise.

### Controls shown

1. **Capability minimization:** repository deletion, workflow execution, and
   release publication are removed from `tools/list`.
2. **Untrusted-content taint:** reading the external PR taints the Jac session.
3. **DLP:** GitHub PAT, AWS access key, AWS secret, JWT, and email are redacted
   from CI logs. Audit stores entity counts only.
4. **Protected-branch constraint:** a direct push to `main` is denied before it
   reaches GitHub.
5. **Taint sink gate:** changing to a normally valid `agent/*` branch does not
   bypass the compromised-session control.
6. **Least-privilege continuity:** safe code search still works in the elevated
   session; the gateway does not reduce every incident to a blanket outage.
7. **Argument rewrite:** in a clean session, a proposed pull request is forced
   to `draft=true`.
8. **Human boundary:** release publication fails closed when no approver is
   configured.
9. **Sequence rule:** workflow execution is independently blocked after CI log
   access, even in an otherwise clean session.

Expected closing line:

> Supply-chain attack contained; useful development work survived.

## Scenario 2 — critical: Slack prompt injection and exfiltration

### Attack

A Slack Connect guest poisons a support-channel message. It directs the agent
to search workspace messages for credentials and customer identity data,
download a production environment file, create an external DM, and send the
collected material. The attack tries multiple exfiltration routes after the
first is denied.

### Controls shown

1. **Capability minimization:** outbound messages, drafts, conversations, and
   canvases that require approval are absent from `tools/list`.
2. **Untrusted-content taint:** reading the guest message taints the session.
3. **Strict DLP:** email, SSN, Slack token, API key, and JWT are removed from a
   workspace-wide search result.
4. **Proportional access:** a low-bandwidth reaction remains usable after
   taint.
5. **Quarantine:** an opaque credentials file is withheld in full rather than
   being guessed safe.
6. **Channel ACL:** direct access to `#exec` is denied.
7. **Primary sink gate:** sending an external DM is blocked before Slack sees
   it.
8. **Fallback sink gate:** creating a new conversation is also blocked.
9. **Risk suspension:** accumulated violations suspend the session, after
   which even normally safe metadata reads are denied.
10. **Approval fail-closed:** a separate clean session still cannot send a
    message without a human approver.

Expected closing line:

> Every exfiltration route failed and the compromised session was suspended.

## Evidence to show after the run

Every run creates a timestamped directory under `jac/demo_output/` containing:

- `*.audit.jsonl` — decisions, walker traces, redaction counts, risk, and taint;
- `attack-lifecycle.audit.jsonl` — a dashboard-ready bundle of all four sessions;
- `*.upstream-calls.log` — tool names received by each mock server.

The demo asserts all of the following before printing `PASS`:

- every expected allow or block occurred;
- blocked calls are absent from the upstream-call logs;
- all planted sensitive values are absent from client responses;
- audit files contain no arguments, raw results, scrubbed values, or planted
  secrets.

These evidence files are intentionally ignored by Git. They are runtime proof,
not source artifacts.

## Suggested five-minute talk track

1. **Problem (20 seconds):** “Agents can legitimately read data and mutate
   systems, but a malicious message can connect those powers into an attack.”
2. **Architecture (30 seconds):** show the five Jac graph stages and explain
   first-deny-wins.
3. **GitHub (90 seconds):** emphasize secret redaction, two independent write
   blocks, draft rewriting, and the release approval boundary.
4. **Slack (90 seconds):** emphasize multi-route exfiltration, quarantine,
   proportional access, and automatic suspension.
5. **Evidence (40 seconds):** open one audit file and one upstream-call log.
   Point out that security telemetry has counts and decisions, never payloads.
6. **Close (20 seconds):** “The model and MCP servers did not change. Jac
   inserted enforceable policy between them, and safe work continued.”

## Live-service upgrade after the hackathon

The policies and wrapper are already separated from the deterministic demo
servers. A later integration can replace each local mock command with the real
GitHub or Slack MCP server command while keeping the Jac gateway, policies,
tests, and audit contract. Do not use live organizational credentials for the
stage demo.
