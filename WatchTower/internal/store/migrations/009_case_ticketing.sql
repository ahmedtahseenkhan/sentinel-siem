-- Native ticketing on top of cases: auto-create grouping, SLA tracking,
-- escalation flags, and a full state-change audit trail.

ALTER TABLE cases ADD COLUMN IF NOT EXISTS group_key    TEXT    NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN IF NOT EXISTS due_at       BIGINT  NOT NULL DEFAULT 0;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS sla_breached BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS escalated    BOOLEAN NOT NULL DEFAULT FALSE;

-- group_key identifies the (rule + agent) an auto-created case belongs to, so
-- repeat alerts append to the existing open case instead of spawning new ones.
CREATE INDEX IF NOT EXISTS idx_cases_group_key ON cases(group_key) WHERE group_key <> '';

-- The SLA sweeper scans for open, not-yet-breached cases past their due date.
CREATE INDEX IF NOT EXISTS idx_cases_sla ON cases(status, due_at);

CREATE TABLE IF NOT EXISTS case_history (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    actor      TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL DEFAULT '',  -- created | status_changed | assignee_changed | priority_changed | sla_breached
    field      TEXT NOT NULL DEFAULT '',
    old_value  TEXT NOT NULL DEFAULT '',
    new_value  TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_case_history_case ON case_history(case_id);
