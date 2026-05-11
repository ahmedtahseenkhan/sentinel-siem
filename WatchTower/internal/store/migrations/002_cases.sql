CREATE TABLE IF NOT EXISTS cases (
    id          BIGSERIAL PRIMARY KEY,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'open',
    priority    TEXT NOT NULL DEFAULT 'medium',
    severity    INTEGER NOT NULL DEFAULT 0,
    assignee    TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  BIGINT NOT NULL DEFAULT 0,
    updated_at  BIGINT NOT NULL DEFAULT 0,
    closed_at   BIGINT NOT NULL DEFAULT 0,
    tags        JSONB NOT NULL DEFAULT '[]',
    alert_ids   JSONB NOT NULL DEFAULT '[]',
    agent_ids   JSONB NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS case_notes (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author     TEXT NOT NULL DEFAULT '',
    content    TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS case_evidence (
    id       BIGSERIAL PRIMARY KEY,
    case_id  BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    title    TEXT NOT NULL DEFAULT '',
    type     TEXT NOT NULL DEFAULT 'log',
    content  TEXT NOT NULL DEFAULT '',
    added_by TEXT NOT NULL DEFAULT '',
    added_at BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_cases_status    ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_priority  ON cases(priority);
CREATE INDEX IF NOT EXISTS idx_cases_assignee  ON cases(assignee);
CREATE INDEX IF NOT EXISTS idx_cases_created   ON cases(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id);
CREATE INDEX IF NOT EXISTS idx_case_evid_case  ON case_evidence(case_id);
