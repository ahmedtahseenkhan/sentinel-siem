CREATE TABLE IF NOT EXISTS identity_users (
    id            BIGSERIAL PRIMARY KEY,
    sam_account   TEXT UNIQUE NOT NULL,
    display_name  TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    department    TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL DEFAULT '',
    manager       TEXT NOT NULL DEFAULT '',
    groups        JSONB NOT NULL DEFAULT '[]',
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    last_logon    BIGINT NOT NULL DEFAULT 0,
    bad_pwd_count INTEGER NOT NULL DEFAULT 0,
    raw_attrs     JSONB NOT NULL DEFAULT '{}',
    synced_at     BIGINT NOT NULL DEFAULT 0,
    source        TEXT NOT NULL DEFAULT 'ldap'
);

CREATE INDEX IF NOT EXISTS idx_id_users_sam     ON identity_users(sam_account);
CREATE INDEX IF NOT EXISTS idx_id_users_enabled ON identity_users(enabled);
CREATE INDEX IF NOT EXISTS idx_id_users_dept    ON identity_users(department);
