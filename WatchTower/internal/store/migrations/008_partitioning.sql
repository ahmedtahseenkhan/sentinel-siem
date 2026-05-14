-- Migration 008: Convert alerts to time-partitioned table + archiving infrastructure
-- Idempotent: skips entirely if alerts is already partitioned.

DO $$
DECLARE
    max_id    BIGINT;
    part_name TEXT;
    d         DATE;
BEGIN
    -- Guard: skip if alerts is already a partitioned table
    IF EXISTS (
        SELECT 1 FROM pg_partitioned_table pt
        JOIN pg_class c ON c.oid = pt.partrelid
        WHERE c.relname = 'alerts' AND c.relnamespace = 'public'::regnamespace
    ) THEN
        RAISE NOTICE 'alerts already partitioned — skipping 008';
        RETURN;
    END IF;

    RAISE NOTICE 'Converting alerts to PARTITION BY RANGE (timestamp) ...';

    -- 1. Snapshot current max id so the sequence continues without gaps
    SELECT COALESCE(MAX(id), 0) INTO max_id FROM alerts;

    -- 2. Rename existing table; rename its indexes to avoid name collision
    ALTER TABLE alerts RENAME TO alerts_legacy;
    ALTER INDEX IF EXISTS idx_alerts_agent     RENAME TO idx_alerts_legacy_agent;
    ALTER INDEX IF EXISTS idx_alerts_timestamp RENAME TO idx_alerts_legacy_timestamp;
    ALTER INDEX IF EXISTS idx_alerts_level     RENAME TO idx_alerts_legacy_level;

    -- 3. Detach the old BIGSERIAL sequence so we can reuse it
    ALTER SEQUENCE alerts_id_seq OWNED BY NONE;

    -- 4. Create the partitioned parent table
    --    PK must include partition key (timestamp) per Postgres requirement.
    CREATE TABLE alerts (
        id          BIGINT      NOT NULL DEFAULT nextval('alerts_id_seq'),
        rule_id     INTEGER     NOT NULL,
        level       INTEGER     NOT NULL DEFAULT 0,
        agent_id    TEXT        NOT NULL DEFAULT '',
        timestamp   BIGINT      NOT NULL DEFAULT 0,
        title       TEXT        NOT NULL DEFAULT '',
        description TEXT        NOT NULL DEFAULT '',
        event_data  TEXT        NOT NULL DEFAULT '{}',
        rule_groups TEXT        NOT NULL DEFAULT '[]',
        forwarded   BOOLEAN     NOT NULL DEFAULT FALSE,
        PRIMARY KEY (id, timestamp)
    ) PARTITION BY RANGE (timestamp);

    -- Advance the sequence past the highest existing id
    PERFORM setval('alerts_id_seq', GREATEST(max_id + 1, 1), FALSE);

    -- 5. Indexes on the parent — inherited automatically by every partition
    CREATE INDEX idx_alerts_agent     ON alerts (agent_id);
    CREATE INDEX idx_alerts_timestamp ON alerts (timestamp DESC);
    CREATE INDEX idx_alerts_level     ON alerts (level);
    -- Partial index: only unforwarded rows (used by the forwarder)
    CREATE INDEX idx_alerts_unforwarded ON alerts (id) WHERE NOT forwarded;

    -- 6. Helper: create one monthly partition covering [start, end) in epoch-ms
    --    Named alerts_YYYY_MM so it sorts lexicographically by time.
    CREATE OR REPLACE FUNCTION create_alerts_partition(yr INTEGER, mo INTEGER)
    RETURNS VOID LANGUAGE plpgsql AS $fn$
    DECLARE
        start_ts  BIGINT;
        end_ts    BIGINT;
        pname     TEXT;
    BEGIN
        start_ts := EXTRACT(EPOCH FROM make_timestamptz(yr, mo, 1, 0, 0, 0, 'UTC'))::BIGINT * 1000;
        end_ts   := EXTRACT(EPOCH FROM (make_timestamptz(yr, mo, 1, 0, 0, 0, 'UTC') + INTERVAL '1 month'))::BIGINT * 1000;
        -- Use lpad instead of %d — PostgreSQL format() only supports %s/%I/%L
        pname    := 'alerts_' || lpad(yr::TEXT, 4, '0') || '_' || lpad(mo::TEXT, 2, '0');
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF alerts FOR VALUES FROM (%s) TO (%s)',
            pname, start_ts, end_ts
        );
    END;
    $fn$;

    -- 7. Pre-create partitions: 3 months back → 12 months ahead
    FOR d IN
        SELECT generate_series(
            date_trunc('month', NOW()) - INTERVAL '3 months',
            date_trunc('month', NOW()) + INTERVAL '12 months',
            INTERVAL '1 month'
        )::DATE
    LOOP
        PERFORM create_alerts_partition(
            EXTRACT(YEAR  FROM d)::INTEGER,
            EXTRACT(MONTH FROM d)::INTEGER
        );
    END LOOP;

    -- 8. Migrate existing rows into the partitioned table, then drop legacy
    INSERT INTO alerts
        SELECT id, rule_id, level, agent_id, timestamp, title,
               description, event_data, rule_groups, forwarded
        FROM alerts_legacy;

    DROP TABLE alerts_legacy;

    RAISE NOTICE 'alerts partitioned successfully (% rows migrated, max_id=%)', max_id, max_id;
END;
$$;

-- ── Archive table (cold storage, unpartitioned) ─────────────────────────────
-- Holds forwarded alerts older than the retention window.
-- Schema mirrors alerts except id is BIGINT (not sequence-backed).
CREATE TABLE IF NOT EXISTS alerts_archive (
    id          BIGINT   NOT NULL,
    rule_id     INTEGER  NOT NULL,
    level       INTEGER  NOT NULL DEFAULT 0,
    agent_id    TEXT     NOT NULL DEFAULT '',
    timestamp   BIGINT   NOT NULL DEFAULT 0,
    title       TEXT     NOT NULL DEFAULT '',
    description TEXT     NOT NULL DEFAULT '',
    event_data  TEXT     NOT NULL DEFAULT '{}',
    rule_groups TEXT     NOT NULL DEFAULT '[]',
    forwarded   BOOLEAN  NOT NULL DEFAULT FALSE,
    archived_at BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS idx_archive_agent     ON alerts_archive (agent_id);
CREATE INDEX IF NOT EXISTS idx_archive_timestamp ON alerts_archive (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_archive_level     ON alerts_archive (level);

-- ── Maintenance functions ────────────────────────────────────────────────────

-- Ensure partitions exist from now up to months_ahead months in the future.
-- Call on every startup + monthly cron.
CREATE OR REPLACE FUNCTION create_alerts_partition(yr INTEGER, mo INTEGER)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    start_ts BIGINT;
    end_ts   BIGINT;
    pname    TEXT;
BEGIN
    start_ts := EXTRACT(EPOCH FROM make_timestamptz(yr, mo, 1, 0, 0, 0, 'UTC'))::BIGINT * 1000;
    end_ts   := EXTRACT(EPOCH FROM (make_timestamptz(yr, mo, 1, 0, 0, 0, 'UTC') + INTERVAL '1 month'))::BIGINT * 1000;
    pname    := 'alerts_' || lpad(yr::TEXT, 4, '0') || '_' || lpad(mo::TEXT, 2, '0');
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF alerts FOR VALUES FROM (%s) TO (%s)',
        pname, start_ts, end_ts
    );
END;
$$;

CREATE OR REPLACE FUNCTION ensure_future_partitions(months_ahead INTEGER DEFAULT 3)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE d DATE;
BEGIN
    FOR d IN
        SELECT generate_series(
            date_trunc('month', NOW()),
            date_trunc('month', NOW()) + (months_ahead || ' months')::INTERVAL,
            INTERVAL '1 month'
        )::DATE
    LOOP
        PERFORM create_alerts_partition(
            EXTRACT(YEAR  FROM d)::INTEGER,
            EXTRACT(MONTH FROM d)::INTEGER
        );
    END LOOP;
END;
$$;

-- Move forwarded alerts older than retention_days into alerts_archive,
-- then DELETE them from the live partitioned table.
-- Returns the number of rows archived.
CREATE OR REPLACE FUNCTION archive_old_alerts(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
    cutoff_ts BIGINT;
    n         INTEGER;
BEGIN
    cutoff_ts := (EXTRACT(EPOCH FROM NOW())::BIGINT - retention_days * 86400) * 1000;

    WITH moved AS (
        DELETE FROM alerts
        WHERE forwarded = TRUE
          AND timestamp < cutoff_ts
        RETURNING id, rule_id, level, agent_id, timestamp, title,
                  description, event_data, rule_groups, forwarded
    )
    INSERT INTO alerts_archive (id, rule_id, level, agent_id, timestamp, title,
                                description, event_data, rule_groups, forwarded)
        SELECT id, rule_id, level, agent_id, timestamp, title,
               description, event_data, rule_groups, forwarded
        FROM moved
    ON CONFLICT (id) DO NOTHING;

    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$;

-- Delete expired RBA risk events (expires_at < now).
-- rba_risk_events grows 1 row per alert; prune it regularly.
-- Returns number of rows deleted.
CREATE OR REPLACE FUNCTION purge_expired_rba_events()
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
    n      INTEGER;
    now_ms BIGINT;
BEGIN
    now_ms := EXTRACT(EPOCH FROM NOW())::BIGINT * 1000;
    DELETE FROM rba_risk_events WHERE expires_at > 0 AND expires_at < now_ms;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$;

-- Drop empty partitions older than months_keep months (they've been archived).
-- Safe to call monthly.
CREATE OR REPLACE FUNCTION drop_empty_old_partitions(months_keep INTEGER DEFAULT 6)
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
    cutoff DATE;
    part   RECORD;
    n      INTEGER := 0;
    cnt    BIGINT;
BEGIN
    cutoff := date_trunc('month', NOW()) - (months_keep || ' months')::INTERVAL;

    FOR part IN
        SELECT c.relname AS pname
        FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'alerts'
          AND c.relname ~ '^alerts_\d{4}_\d{2}$'
          AND to_date(substring(c.relname FROM 8), 'YYYY_MM') < cutoff
    LOOP
        EXECUTE format('SELECT COUNT(*) FROM %I', part.pname) INTO cnt;
        IF cnt = 0 THEN
            EXECUTE format('DROP TABLE IF EXISTS %I', part.pname);
            n := n + 1;
            RAISE NOTICE 'Dropped empty partition %', part.pname;
        END IF;
    END LOOP;
    RETURN n;
END;
$$;
