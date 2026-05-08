CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    group_id TEXT NOT NULL DEFAULT '',
    labels TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    ip_address TEXT NOT NULL DEFAULT '',
    last_heartbeat INTEGER NOT NULL DEFAULT 0,
    registered_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agent_groups (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    config_overrides TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    level INTEGER NOT NULL DEFAULT 0,
    agent_id TEXT NOT NULL DEFAULT '',
    timestamp INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    event_data TEXT NOT NULL DEFAULT '{}',
    rule_groups TEXT NOT NULL DEFAULT '[]',
    forwarded INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS active_responses (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    parameters TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL DEFAULT 0,
    executed_at INTEGER NOT NULL DEFAULT 0,
    result TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_group ON agents(group_id);
CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level);
CREATE INDEX IF NOT EXISTS idx_active_responses_agent ON active_responses(agent_id);
