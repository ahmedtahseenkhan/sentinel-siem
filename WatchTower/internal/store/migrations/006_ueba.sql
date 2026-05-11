-- Behavioral baselines per entity (updated hourly)
CREATE TABLE IF NOT EXISTS ueba_baselines (
    id           BIGSERIAL PRIMARY KEY,
    entity_id    TEXT NOT NULL,
    entity_type  TEXT NOT NULL DEFAULT 'agent',
    metric       TEXT NOT NULL,        -- alert_rate, critical_rate, event_rate
    avg_value    DOUBLE PRECISION NOT NULL DEFAULT 0,
    std_dev      DOUBLE PRECISION NOT NULL DEFAULT 0,
    sample_count INTEGER NOT NULL DEFAULT 0,
    computed_at  BIGINT NOT NULL DEFAULT 0,
    UNIQUE (entity_id, metric)
);

-- Detected anomalies
CREATE TABLE IF NOT EXISTS ueba_anomalies (
    id           BIGSERIAL PRIMARY KEY,
    entity_id    TEXT NOT NULL,
    entity_type  TEXT NOT NULL DEFAULT 'agent',
    anomaly_type TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'medium',
    score        INTEGER NOT NULL DEFAULT 0,
    detected_at  BIGINT NOT NULL DEFAULT 0,
    alert_id     BIGINT NOT NULL DEFAULT 0,
    resolved     BOOLEAN NOT NULL DEFAULT FALSE
);

-- Aggregated risk scores (one row per entity, upserted hourly)
CREATE TABLE IF NOT EXISTS ueba_risk_scores (
    entity_id        TEXT PRIMARY KEY,
    entity_type      TEXT NOT NULL DEFAULT 'agent',
    risk_score       INTEGER NOT NULL DEFAULT 0,
    risk_level       TEXT NOT NULL DEFAULT 'low',
    alert_count_7d   INTEGER NOT NULL DEFAULT 0,
    critical_count_7d INTEGER NOT NULL DEFAULT 0,
    anomaly_count_7d INTEGER NOT NULL DEFAULT 0,
    last_alert       BIGINT NOT NULL DEFAULT 0,
    updated_at       BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ueba_baselines_entity ON ueba_baselines(entity_id);
CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_entity ON ueba_anomalies(entity_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_time   ON ueba_anomalies(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_ueba_risk_score       ON ueba_risk_scores(risk_score DESC);
