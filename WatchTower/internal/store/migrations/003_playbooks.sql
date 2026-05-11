CREATE TABLE IF NOT EXISTS playbooks (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    trigger     JSONB NOT NULL DEFAULT '{}',
    actions     JSONB NOT NULL DEFAULT '[]',
    created_at  BIGINT NOT NULL DEFAULT 0,
    updated_at  BIGINT NOT NULL DEFAULT 0,
    run_count   BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS playbook_executions (
    id           BIGSERIAL PRIMARY KEY,
    playbook_id  BIGINT NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    alert_id     BIGINT NOT NULL DEFAULT 0,
    agent_id     TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'running',
    started_at   BIGINT NOT NULL DEFAULT 0,
    completed_at BIGINT NOT NULL DEFAULT 0,
    results      JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON playbooks(enabled);
CREATE INDEX IF NOT EXISTS idx_pb_exec_playbook  ON playbook_executions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_pb_exec_status    ON playbook_executions(status);
CREATE INDEX IF NOT EXISTS idx_pb_exec_started   ON playbook_executions(started_at DESC);
