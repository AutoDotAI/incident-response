# AutoDotAI incident-response

A small, deterministic incident responder for RunGuard's **local** alerts. The
policy is in this repository; the application supplies a trusted adapter for
PostgreSQL records, ownership checks, and its narrowly gated demo control.
This package contains no RunGuard database models, model integration, HTTP
client, credentials, or deployment commands.

## Install and test

Requires Python 3.12 or newer and `uv`. From a checkout of this repository:

```bash
uv sync --locked --extra test
uv run --no-sync pytest -q
```

The CLI accepts an **operator-supplied trusted adapter** factory. It does not
connect to RunGuard by itself:

```bash
incident-response --adapter my_integration:create_adapter once
incident-response --adapter my_integration:create_adapter inspect ALERT_ID OWNER_ID
incident-response --adapter my_integration:create_adapter serve
```

The integration factory returns an object implementing `ResponderAdapter` in
`src/incident_response/policy.py`. RunGuard will provide that adapter in its
optional responder profile. `once` processes persisted open alerts; `serve`
polls every five seconds; `inspect` requires an owned alert and owner ID.
The adapter must atomically reserve one incident/action per alert and enforce
the exact paused demo binding again when `resume_demo_worker` is called.

## Fixed behavior

The only inspections are worker health, the owned failed run, recent **coded**
errors, and owned queue depth. Evidence includes safe IDs, event/error codes,
and bounded counts; raw log messages, fetched pages, URLs, tokens, and model
text are excluded. Target-site failures are diagnosed separately from worker
failures. Failed user runs are never retried automatically.

The only possible automatic action is one audited `resume_demo_worker` for an
exactly bound, paused local demo fixture. Outside that gate the incident is
read-only and requires operator approval. A changed gate or recovery timeout
is recorded as needing review. This package does not expose a public incident
endpoint or production remediation capability.

See [RunGuard issue #89](https://github.com/AutoDotAI/RunGuard/issues/89) for
the extraction task and [#90](https://github.com/AutoDotAI/RunGuard/issues/90)
for the optional RunGuard integration.
