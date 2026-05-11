CREATE TABLE IF NOT EXISTS rule_versions (
    id          BIGSERIAL PRIMARY KEY,
    rule_file   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    content     TEXT NOT NULL,
    commit_msg  TEXT NOT NULL DEFAULT '',
    author      TEXT NOT NULL DEFAULT 'system',
    created_at  BIGINT NOT NULL DEFAULT 0,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_rv_file   ON rule_versions(rule_file, version DESC);
CREATE INDEX IF NOT EXISTS idx_rv_active ON rule_versions(rule_file, is_active);

-- View: latest active version per file (for quick lookups)
CREATE OR REPLACE VIEW rule_version_latest AS
SELECT DISTINCT ON (rule_file)
    rule_file, version, content, commit_msg, author, created_at, is_active
FROM rule_versions
WHERE is_active = TRUE
ORDER BY rule_file, version DESC;
