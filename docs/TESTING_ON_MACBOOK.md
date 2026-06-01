# Stage 1 — Testing Sentinel SIEM on your MacBook

This is the **first** stage of validating a release before you touch the VM lab or a
client. Everything runs in Docker Desktop on your Mac, end to end, with **two simulated
agents already wired in** — so within a few minutes you can confirm the rule engine,
indexing, and dashboard all work before deploying anything to real machines.

> Stack file: **`docker-compose.local.yaml`** (single-node OpenSearch, one WatchTower,
> one WatchVault, Postgres, Kafka, **two WatchNode agents**, and the dashboard).
> Do **not** use `docker-compose.full.yaml` locally — it's the multi-node production
> topology and uses different service names/volumes.

---

## 0. Prerequisites (one-time)

- **Docker Desktop** for Mac (you have Docker 29.x). Open it and make sure it's running.
- Give Docker Desktop enough memory: **Settings → Resources → Memory ≥ 4 GB**
  (OpenSearch alone wants 1 GB heap). 6–8 GB is comfortable.
- (Optional, only if you want to run the agent natively on macOS) **Go 1.21+** —
  `brew install go`.

---

## 1. Bring the whole stack up

From the repo root (`/Users/tahseenkhan/Documents/python/Go`):

```bash
docker compose -f docker-compose.local.yaml up -d --build
```

- `--build` is needed the first time (and after code changes) because WatchTower,
  WatchVault, the agents, and the dashboard are all built from source.
- First build pulls base images and compiles Go — expect a few minutes. Subsequent
  starts are seconds.

Watch it come healthy:

```bash
docker compose -f docker-compose.local.yaml ps
```

Wait until `opensearch` and `kafka` show **healthy** and the rest show **running**.
OpenSearch can take ~60s on the first boot.

---

## 2. Verify each layer

Run these from your Mac terminal — all ports are published to `localhost`.

**a) OpenSearch is up and has indices forming:**
```bash
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
curl -s http://localhost:9200/_cat/indices?v
```
You're looking for cluster status `green`/`yellow` and, after a minute or two,
`watchvault-*` indices appearing.

**b) WatchTower sees the two built-in agents:**
```bash
curl -s -H "X-API-Key: sentinel-dev-api-key" http://localhost:9400/api/v1/agents | python3 -m json.tool
```
You should see `node-local-01` and `node-local-02` with a recent last-seen time.
(The API key is `sentinel-dev-api-key`, set in the compose file.)

**c) The dashboard:**
Open <http://localhost:5050> → log in with **`admin` / `admin`**
(super-admin is `superadmin` / `superadmin`).
- **Agents** page → both `node-local-*` agents listed.
- **Discover** page → events flowing in after a couple of minutes.

If all three pass, the build is good and you can move to **Stage 2 (the VM lab)**.

---

## 3. Generate a test detection (optional but recommended)

The two agents emit system/process/network telemetry, but to confirm the **rule
engine fires** you can run the per-role pipeline tests, which exercise the same engine
against known-bad fixtures:

```bash
cd WatchTower
go test -race -v -run TestRolePipeline ./internal/engine/
```

Green here means the loaded rule set actually produces alerts for AD / IIS / MSSQL /
Apache / sshd fixtures. This is the fastest "are detections working" check and needs
no live agent.

---

## 4. (Optional) Run a *native* macOS agent against the local stack

The two `watchnode` containers are enough for most smoke tests. But if you want a real
agent process reporting from your Mac host (useful for testing FIM/log collectors on a
real filesystem), build and run a darwin binary:

```bash
cd WatchNode/cmd/agent
go build -o watchnode-darwin .
```

Create `~/watchnode-mac.yaml`:

```yaml
agent:
  name: "macbook-test"
manager:
  url: "127.0.0.1:50051"          # gRPC port published by the local stack
  enroll_token: "sentinel-enroll-secret-2024"   # MUST match WATCHTOWER_GRPC_ENROLL_TOKEN
  reconnect:
    max_attempts: 0
    initial_backoff: "2s"
    max_backoff: "60s"
collectors:
  system:   { enabled: true, interval: "30s" }
  process:  { enabled: true, interval: "30s" }
  network:  { enabled: true, interval: "120s" }
  file_integrity:
    enabled: true
    interval: "5m"
    paths:
      - { path: "/etc", recursive: true }
  logs:
    enabled: true
    sources:
      - { type: file, path: "/var/log/system.log", tags: [system] }
```

Run it in the foreground so you can watch the connect logs:

```bash
./watchnode-darwin --config ~/watchnode-mac.yaml
```

You should see it connect to the manager and start collectors. Within ~30s it appears
as `macbook-test` on the dashboard **Agents** page. `Ctrl+C` to stop.

> The agent's config flag is `--config`. The `enroll_token` under `manager:` is what
> gets the agent admitted — if it's wrong/missing, the manager rejects the stream.

---

## 5. Tear down

```bash
# stop, keep data volumes (fast restart, history preserved)
docker compose -f docker-compose.local.yaml down

# stop AND wipe OpenSearch/Postgres data (clean slate)
docker compose -f docker-compose.local.yaml down -v
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `opensearch` keeps restarting / unhealthy | Raise Docker Desktop memory to ≥ 4 GB. Check `docker compose -f docker-compose.local.yaml logs opensearch`. |
| Dashboard 502 / won't load | OpenSearch or WatchTower not healthy yet — wait, then `docker compose ... ps`. |
| `/api/v1/agents` returns 401 | Missing/incorrect `X-API-Key: sentinel-dev-api-key` header. |
| Native mac agent won't connect | Confirm port `50051` is published (`docker compose ... ps`), and `enroll_token` matches `sentinel-enroll-secret-2024`. |
| Build fails on `go build` | Need Go 1.21+ (`go version`). |

When Stage 1 is green, continue to **[CLIENT_DEPLOYMENT_AND_VM_TESTING.md](CLIENT_DEPLOYMENT_AND_VM_TESTING.md)**.
