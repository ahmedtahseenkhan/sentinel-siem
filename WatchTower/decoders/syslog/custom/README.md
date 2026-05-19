# Custom Syslog Decoders

Drop your own YAML decoder files here. They are hot-reloaded every 30 seconds — no restart needed.

## Format

```yaml
group: my-app
description: "Decoders for MyApp"

decoders:
  # Root decoder — matches syslog program name
  - name: myapp
    program: "^myapp$"
    description: "Root MyApp decoder"

  # Child decoder — only runs if parent matched
  - name: myapp-login
    parent: myapp
    prematch: "user login"
    regex: "user login: user=(?P<user>\\S+) from=(?P<src_ip>\\S+)"
    static_fields:
      action: login
      category: authentication
```

## Fields

| Field | Description |
|-------|-------------|
| `name` | Unique decoder name (required) |
| `parent` | Parent decoder name — child only runs if parent matched first |
| `program` | Regex matched against syslog `app_name` (root decoders only) |
| `prematch` | Fast string/regex check on the message before running full regex |
| `regex` | Named capture groups `(?P<field>...)` populate event fields |
| `order` | Positional field names for unnamed capture groups |
| `static_fields` | Fixed key=value fields added when this decoder matches |

## API

You can also manage custom decoders via the REST API:

- `GET  /api/v1/decoders/syslog`            — list all
- `POST /api/v1/decoders/syslog`            — create a custom decoder
- `DELETE /api/v1/decoders/syslog/:name`    — delete a custom decoder
- `POST /api/v1/decoders/syslog/test`       — test a message
- `POST /api/v1/decoders/syslog/reload`     — force reload from disk
