# Jac MCP Security Gateway

This directory contains the hackathon-focused Jac implementation of the
gateway's security decision engine. Jac owns policy matching, graph-persistent
session taint and risk, constraints, rewrites, response redaction, and the
first-deny-wins enforcement walker. The existing Python project remains the
production transport, console, storage, and integration layer.

## Why Jac

The enforcement pipeline is modeled as a graph:

```text
root -> SessionGate -> PolicyMatch -> ConstraintGate -> SequenceGate -> ActionStage
```

Every MCP `tools/call` becomes a `CallWalker`. The walker carries a typed
`CallContext`, visits each security stage, and uses `disengage` to stop
immediately on denial. Persistent `Session` nodes remember taint, history, and
risk across calls.

## Advanced hackathon demo

The judge-facing demo contains a high-severity GitHub supply-chain attack and a
critical Slack prompt-injection/exfiltration attack. Together they exercise
tool hiding, role-aware policy, DLP, quarantine, constraints, rewrites, taint,
sequence rules, approval gates, risk escalation, session suspension, and safe
audit.

From the repository root:

```powershell
.\jac\run_demo.ps1 -Scenario all -Pause
```

Omit `-Pause` for an automatic 10–20 second verification run. Each execution
creates ignored runtime evidence under `jac/demo_output/`, including
counts-only audit records and an upstream tool-name log proving that denied
calls were not forwarded.

See [`../docs/HACKATHON_DEMO.md`](../docs/HACKATHON_DEMO.md) for the full
five-minute talk track, expected results, and rehearsal commands.

## Run locally

Use Python 3.12 or 3.13 and install the pinned Jac compiler once:

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install "jaclang==0.16.7"
& .\.venv\Scripts\jac.exe install
```

Then, from this `jac/` directory:

```powershell
$Jac = ".\.venv\Scripts\jac.exe"
& $Jac clean --data --force
& $Jac check gateway\context.jac gateway\policy.jac gateway\redaction.jac gateway\audit.jac gateway\pipeline.jac transports\wrap.jac
& $Jac test -d tests
& $Jac clean --data --force
& $Jac run demo\attack.jac
```

The demo writes a counts-only audit stream to `attack.audit.jsonl`. It never
records tool arguments, raw results, or redacted values.

## Real MCP wrapper

The Jac wrapper launches the repository's existing Python mock MCP server and
polices newline-delimited JSON-RPC in both directions:

```powershell
& $Jac run -e none transports\wrap.jac policies\mock-crm.yaml jac.audit.jsonl -- python ..\demo\mock_server.py
```

Run the automated end-to-end harness with:

```powershell
& .\.venv\Scripts\python.exe tests\wrap_e2e.py
```

Set `JAC_BIN` if the harness should use a Jac executable outside `.venv`.
