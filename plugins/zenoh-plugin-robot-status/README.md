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
    timeout_secs: 30,
  },
}
```

`robot_id` extraction priority:
1. TLS/QUIC certificate common name
2. fallback to peer zid
