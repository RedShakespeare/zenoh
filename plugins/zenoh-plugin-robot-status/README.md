# zenoh-plugin-robot-status

Dynamic plugin for `zenohd` that observes client transport sessions and reports robot status via:

`PATCH /v1/{project_id}/robots/{robot_id}/status?status=ONLINE|OFFLINE`

## Config

```json5
{
  api_base_url: "https://api.example.com",
  auth_token: "REPLACE_ME",
  project_id: "project-123",
  report_mode: "http", // http | dry_run
  keepalive: {
    mode: "disabled", // disabled | transport_closed_only | inactivity
    timeout_secs: 10,   // used only when mode=inactivity
  },
}
```

`robot_id` extraction priority:
1. TLS/QUIC certificate common name
2. fallback to peer zid

## Local verification script

Run:

```bash
plugins/zenoh-plugin-robot-status/scripts/verify_local.sh
```

Run full keepalive mode matrix test:

```bash
plugins/zenoh-plugin-robot-status/scripts/test_keepalive_modes.sh
```


Optional env vars:
- `ZENOHD_PORT` (default `7448`)
- `BACKEND_PORT` (default `18080`)
- `PROJECT_ID` (default `project-123`)
- `AUTH_TOKEN` (default `demo-token`)
- `REPORT_MODE` (default `http`, supports `http` or `dry_run`)
- `KEEPALIVE_MODE` (default `disabled`)
- `TIMEOUT_SECS` (default `10`, only used for `inactivity`)
- `PLUGIN_SO` (default `./target/debug/libzenoh_plugin_robot_status.so`)


Keepalive modes:
- `disabled`: no timeout scanner, OFFLINE only on transport closed.
- `transport_closed_only`: same behavior as disabled (explicit semantic mode).
- `inactivity`: enable timeout scanner and mark OFFLINE on inactivity timeout.

`report_mode` behavior:
- `http`: send real PATCH to backend.
- `dry_run`: do not call backend, emit structured log lines for each report.
