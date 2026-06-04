-- Forensic artifact bundles uploaded by agents on a collect-artifact command.
CREATE TABLE IF NOT EXISTS forensic_artifacts (
    id         BIGSERIAL PRIMARY KEY,
    agent_id   TEXT NOT NULL,
    filename   TEXT NOT NULL,
    path       TEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_artifacts_agent ON forensic_artifacts(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_artifacts_time  ON forensic_artifacts(created_at DESC);
