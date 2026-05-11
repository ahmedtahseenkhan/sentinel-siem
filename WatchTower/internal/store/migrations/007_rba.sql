-- Risk weight overrides per rule (defaults derived from alert level)
CREATE TABLE IF NOT EXISTS rba_rule_weights (
    rule_id     INTEGER PRIMARY KEY,
    risk_weight INTEGER NOT NULL DEFAULT 10,
    description TEXT NOT NULL DEFAULT '',
    updated_at  BIGINT NOT NULL DEFAULT 0
);

-- Individual risk events — one created per stored alert
CREATE TABLE IF NOT EXISTS rba_risk_events (
    id          BIGSERIAL PRIMARY KEY,
    entity_id   TEXT NOT NULL,
    entity_type TEXT NOT NULL DEFAULT 'agent',
    rule_id     INTEGER NOT NULL,
    alert_id    BIGINT NOT NULL,
    risk_weight INTEGER NOT NULL,
    timestamp   BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL
);

-- Rolling entity risk scores (upserted on every alert)
CREATE TABLE IF NOT EXISTS rba_entity_risk (
    entity_id      TEXT PRIMARY KEY,
    entity_type    TEXT NOT NULL DEFAULT 'agent',
    current_score  INTEGER NOT NULL DEFAULT 0,
    threshold      INTEGER NOT NULL DEFAULT 100,
    notables_fired INTEGER NOT NULL DEFAULT 0,
    last_notable   BIGINT NOT NULL DEFAULT 0,
    last_event     BIGINT NOT NULL DEFAULT 0,
    updated_at     BIGINT NOT NULL DEFAULT 0
);

-- Risk Notables — created when entity crosses risk threshold
CREATE TABLE IF NOT EXISTS rba_notables (
    id              BIGSERIAL PRIMARY KEY,
    entity_id       TEXT NOT NULL,
    entity_type     TEXT NOT NULL DEFAULT 'agent',
    risk_score      INTEGER NOT NULL,
    trigger_rule_id INTEGER NOT NULL DEFAULT 0,
    description     TEXT NOT NULL DEFAULT '',
    created_at      BIGINT NOT NULL DEFAULT 0,
    case_id         BIGINT NOT NULL DEFAULT 0,
    resolved        BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_rba_events_entity ON rba_risk_events(entity_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_rba_events_time   ON rba_risk_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_rba_notables_time ON rba_notables(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rba_entity_score  ON rba_entity_risk(current_score DESC);
