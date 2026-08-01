# Forwarding the audit trail to a SIEM

The gateway writes every decision to a JSONL **spool** (`audit.log`), the source
of truth. `mcp-gateway audit forward` is a separate, long-running process that
tails that spool and ships batches to a SIEM. It **reads the spool, never the hot
path** — so a slow or down SIEM never stalls a `tools/call`, and because the
watermark only advances after a batch is accepted, an outage drains with **zero
loss** on recovery (at-least-once).

Run it alongside the gateway (its own process, systemd unit, or sidecar
container). It keeps a watermark file (`<audit>.<sink>.wm`) so a restart resumes
exactly where it left off.

## Webhook (any HTTP log collector)

```bash
mcp-gateway audit forward --audit audit.log \
  --sink webhook --url https://collector.example/ingest \
  --format ocsf \
  --header "X-Tenant: acme"
# Bearer auth: --token-env COLLECTOR_TOKEN  (sent as Authorization: Bearer …)
```

Events go up as NDJSON (one JSON object per line). `--format ocsf` (or `ecs`)
normalizes each event for correlation; `--format raw` (default) ships the
gateway's own schema verbatim.

## Splunk HTTP Event Collector

```bash
export SPLUNK_HEC_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
mcp-gateway audit forward --audit audit.log \
  --sink splunk --url https://splunk.example:8088 \
  --token-env SPLUNK_HEC_TOKEN --sourcetype mcp:gateway \
  --format ocsf
```

Each event is wrapped in an HEC envelope carrying the gateway's own timestamp, so
Splunk indexes by decision time, not ingest time.

### A starter Splunk dashboard (OCSF)

With `--format ocsf`, tool calls arrive as OCSF **Application Activity** (class
6006). A few panels to start from:

```spl
# Denials over time (blocked / quarantined / suspended)
sourcetype=mcp:gateway status="Failure"
| timechart count by activity_name

# Top principals hitting the deny path
sourcetype=mcp:gateway status="Failure"
| stats count by actor.user.name | sort -count

# Tool-call volume by app (tool)
sourcetype=mcp:gateway class_uid=6006
| stats count by app.name activity_name
```

The full original event is preserved under `unmapped.*`, so any gateway field
(`unmapped.redaction_count`, `unmapped.risk_score`, …) is still searchable.

## S3 (archive / data lake)

```bash
mcp-gateway audit forward --audit audit.log \
  --sink s3 --bucket my-audit-bucket --prefix mcp-audit \
  --format ocsf
# needs the [s3] extra: pip install 'mcp-gateway[s3]'; standard AWS creds apply
```

Each batch lands as a gzipped NDJSON object under a Hive-style time partition:

```
mcp-audit/dt=2026-07-31/hour=14/1753970400000-500.ndjson.gz
```

The `dt=`/`hour=` layout lets Athena/Glue/Security Lake prune by time. A backlog
drained after an outage is partitioned by the events' **own** timestamps, so it
lands in the hours it belongs to, not all in the recovery hour.

## Spool rotation

Left uncapped, `audit.log` grows without bound. Cap it and it rolls itself —
`audit.log` → `audit.log.00000001` (monotonic, ascending = newer), a fresh live
file, oldest segments pruned beyond `keep`:

```bash
mcp-gateway wrap --audit audit.log --audit-max-bytes 104857600 --audit-keep 10 -- <server>
# central mode: audit: { rotate_bytes: 104857600, keep: 10 } in gateway.yaml
```

**The forwarder follows rotation losslessly.** It resumes by *inode*, not byte
offset, so a rename is invisible to it — a slow or briefly-down forwarder keeps
draining the rotated segment it was on, then the newer ones, then the live file,
in order. If a consumer falls so far behind that a segment is pruned before it is
read, those events are genuinely lost — and the forwarder says so loudly
(`AUDIT GAP: …` on stderr, `on_gap`, and the lag alarm), never silently.

Size `keep` for the longest outage a forwarder must survive: `keep × rotate_bytes`
is the backlog window. With the SIEM archiving durably, rotation is safe to enable.

> The console **index** is a byte-offset live-tail read model and does *not* track
> across rotation — it flags rotation (`reindex` recovers the live segment) rather
> than corrupt or stall silently. With rotation on, treat the SIEM forwarder + S3
> as the archive/query surface and the console as a live ops view.

## Operational notes

- **One process per sink.** Run several `audit forward` processes (each with its
  own `--sink` and watermark) to fan the same spool out to Splunk *and* S3.
- **Lag alarm.** If the unread backlog grows past ~8 MiB the forwarder logs a
  warning to stderr — wire that to your alerting; it means the sink is down.
- **`--once`** drains the current backlog and exits (for cron/testing); omit it
  to run continuously.
- **At-least-once.** A crash between a successful delivery and the watermark
  write re-sends that batch on restart — a duplicate in the SIEM, never a gap in
  the audit trail. Dedupe on the gateway event's spool offset if you need
  exactly-once downstream.
