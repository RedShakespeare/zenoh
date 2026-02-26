# zenoh-plugin-robot-status

Dynamic plugin for `zenohd` that observes client transport sessions and reports robot status via:

`PATCH /v1/{project_id}/robots/{robot_id}/status?status=ONLINE|OFFLINE`

## Config

```json5
{
  api_base_url: "https://api.example.com",
  auth_token: "REPLACE_ME",
  project_id: "project-123",
  keepalive: {
    timeout_secs: 0, // 0 disables timeout scanner
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

Optional env vars:
- `ZENOHD_PORT` (default `7448`)
- `BACKEND_PORT` (default `18080`)
- `PROJECT_ID` (default `project-123`)
- `AUTH_TOKEN` (default `demo-token`)
- `TIMEOUT_SECS` (default `0`)
- `PLUGIN_SO` (default `./target/debug/libzenoh_plugin_robot_status.so`)
