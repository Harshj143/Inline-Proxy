# Contributing

How two or more people work on the MCP Security Gateway together, and how to
author a connector pack (the most common parallel task).

## Working together on the same repo

Use the **collaborator** model, not a fork. Forks are for arms-length,
outside contributors; teammates building together share one repo, one issue
tracker, one CI, one `main`.

1. The repo owner adds each collaborator: GitHub → repo **Settings →
   Collaborators → Add people** → their username. They accept the emailed invite.
2. Each collaborator clones the same repo and installs the dev environment:
   ```bash
   git clone https://github.com/Harshj143/Inline-Proxy
   cd Inline-Proxy
   python3 -m venv .venv && source .venv/bin/activate
   pip install -e '.[server,vault,redis,postgres,dev]'
   ```
3. **Branch per feature; PR to `main`; never push to `main`.** Example split:
   - `feat/github-pack` — the GitHub connector
   - `feat/slack-pack` — the Slack connector
4. Keep branches small and rebased on `main`. Open a draft PR early so CI runs
   and the other person can see progress.

### Why connector packs parallelize cleanly

Each pack lives in its own directory (`connectors/github/`, `connectors/slack/`),
so two people authoring different packs almost never touch the same files.
The shared **connector framework** (`src/mcp_gateway/connectors/`) already
exists — packs are authored on top of it with **no engine changes**. If a pack
seems to need an engine change, that's a design discussion, not a quiet edit;
raise it as an issue first.

## The quality gate (every commit)

```bash
PYTHONPATH=src python3 -m pytest tests/ -q   # all green — you only add tests
python3 -m ruff check src tests              # clean
```

CI runs the same on every PR (Python 3.12 + 3.13). A PR is ready when both pass
and `docs/PLAN.md` reflects any status change.

## Authoring a connector pack

A connector is a curated security bundle for one MCP server. See
`docs/ARCHITECTURE.md` §4 and the reference pack in `connectors/example/`.

1. **Scaffold it.** This writes a complete, default-deny, self-testing skeleton:
   ```bash
   mcp-gateway connectors scaffold github
   ```
2. **Inventory the tools.** Fill `tools.yaml`: every tool the server exposes,
   each classified `read | write | destructive | secret_adjacent`. This is your
   threat surface — do it before writing rules.
3. **Write the policy.** In `policy.yaml`, start from `default_action: block`
   and add the least-powerful action that works for each tool:
   - reads of sensitive data → `redact` with a profile
   - unbounded queries/results → `rewrite` (e.g. cap a limit)
   - secret-adjacent output (logs, CI) → `quarantine`
   - writes / state changes → `require_approval`
   - destructive actions → `block`
   - untrusted inputs → `taint_sources`; outbound/mutating tools → `taint_sinks`,
     with `sequence_rules` for exfiltration paths (read-then-send).
   Use `roles.yaml` (or inline `roles:`) for per-role overlays.
4. **Write goldens.** Every rule gets a case in `policy_tests.yaml`
   (call → expected outcome). Run:
   ```bash
   mcp-gateway policy validate connectors/github/policy.yaml
   mcp-gateway policy test --policy connectors/github/policy.yaml \
                           --tests connectors/github/policy_tests.yaml
   ```
5. **Document the threat model** in `README.md`: what an attacker could do
   through this server, and how each rule prevents it.
6. **Prove it end-to-end** by wrapping the real server:
   ```bash
   mcp-gateway wrap --connector github -- <the real github mcp server cmd>
   ```
7. Add an e2e acceptance test under `tests/e2e/` for the pack's headline defense
   (e.g. a poisoned issue → attempted exfil PR, blocked).

A company adopting your pack customizes it with an override layer, never a fork:

```bash
mcp-gateway wrap --connector github --override my-company.yaml -- <server cmd>
```

## Commit style

Imperative summary line; body explains the *why*. End the body with a
co-author trailer for the model that helped, e.g.:

```
Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```
