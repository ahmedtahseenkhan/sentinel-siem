-- SOC workflow: engineer roster + shift/on-call schedule (feeds the
-- auto-assignment engine), plus SLA "warning" tracking on cases.

CREATE TABLE IF NOT EXISTS soc_engineers (
    sam_account  TEXT PRIMARY KEY,            -- matches identity_users.sam_account
    skill_groups JSONB   NOT NULL DEFAULT '[]', -- e.g. ["windows","cloud","network"]
    tier         INTEGER NOT NULL DEFAULT 1,   -- 1 junior .. 3 senior
    max_load     INTEGER NOT NULL DEFAULT 25,  -- soft cap on concurrent open cases
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   BIGINT  NOT NULL DEFAULT 0,
    updated_at   BIGINT  NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_soc_eng_active ON soc_engineers(active);

-- One row per recurring shift window. Times are minutes-from-midnight UTC so
-- the sweeper can compare without timezone math. on_call rows are the escalation
-- target outside normal coverage.
CREATE TABLE IF NOT EXISTS soc_shifts (
    id          BIGSERIAL PRIMARY KEY,
    sam_account TEXT    NOT NULL REFERENCES soc_engineers(sam_account) ON DELETE CASCADE,
    weekday     INTEGER NOT NULL,             -- 0=Sun .. 6=Sat
    start_min   INTEGER NOT NULL,             -- minutes from 00:00 UTC
    end_min     INTEGER NOT NULL,             -- minutes from 00:00 UTC (may be < start for overnight)
    on_call     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_soc_shifts_eng ON soc_shifts(sam_account);
CREATE INDEX IF NOT EXISTS idx_soc_shifts_day ON soc_shifts(weekday);

-- SLA "warning" (~80% of the window) tracking, complementing due_at/sla_breached.
ALTER TABLE cases ADD COLUMN IF NOT EXISTS warn_at BIGINT  NOT NULL DEFAULT 0;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS warned  BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_cases_warn ON cases(status, warn_at);

-- False-positive reason captured when a case is resolved as a false positive.
ALTER TABLE cases ADD COLUMN IF NOT EXISTS fp_reason TEXT NOT NULL DEFAULT '';
