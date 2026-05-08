"""
custom_store.py — SQLite persistence for custom visualizations and dashboards.
"""
import sqlite3, json, uuid, os, time

DB_PATH = os.path.join(os.path.dirname(__file__), "custom_dashboards.db")

def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS visualizations (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            viz_type TEXT NOT NULL,
            datasource TEXT NOT NULL DEFAULT 'watchvault-alerts-*',
            config TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS dashboards (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            widgets TEXT NOT NULL DEFAULT '[]',
            time_filter TEXT NOT NULL DEFAULT '24h',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )""")

# Visualizations CRUD
def list_visualizations():
    with _conn() as c:
        rows = c.execute("SELECT * FROM visualizations ORDER BY updated_at DESC").fetchall()
        return [dict(r) | {"config": json.loads(r["config"])} for r in rows]

def get_visualization(viz_id):
    with _conn() as c:
        r = c.execute("SELECT * FROM visualizations WHERE id=?", (viz_id,)).fetchone()
        if not r: return None
        return dict(r) | {"config": json.loads(r["config"])}

def create_visualization(title, viz_type, datasource, config):
    now = time.time()
    vid = str(uuid.uuid4())
    with _conn() as c:
        c.execute("INSERT INTO visualizations VALUES (?,?,?,?,?,?,?)",
                  (vid, title, viz_type, datasource, json.dumps(config), now, now))
    return get_visualization(vid)

def update_visualization(viz_id, title=None, viz_type=None, datasource=None, config=None):
    now = time.time()
    with _conn() as c:
        row = c.execute("SELECT * FROM visualizations WHERE id=?", (viz_id,)).fetchone()
        if not row: return None
        c.execute("""UPDATE visualizations SET
            title=?, viz_type=?, datasource=?, config=?, updated_at=?
            WHERE id=?""",
            (title or row["title"], viz_type or row["viz_type"],
             datasource or row["datasource"],
             json.dumps(config) if config is not None else row["config"],
             now, viz_id))
    return get_visualization(viz_id)

def delete_visualization(viz_id):
    with _conn() as c:
        c.execute("DELETE FROM visualizations WHERE id=?", (viz_id,))

# Dashboards CRUD
def list_dashboards():
    with _conn() as c:
        rows = c.execute("SELECT * FROM dashboards ORDER BY updated_at DESC").fetchall()
        return [dict(r) | {"widgets": json.loads(r["widgets"])} for r in rows]

def get_dashboard(dash_id):
    with _conn() as c:
        r = c.execute("SELECT * FROM dashboards WHERE id=?", (dash_id,)).fetchone()
        if not r: return None
        return dict(r) | {"widgets": json.loads(r["widgets"])}

def create_dashboard(title, description="", widgets=None, time_filter="24h"):
    now = time.time()
    did = str(uuid.uuid4())
    with _conn() as c:
        c.execute("INSERT INTO dashboards VALUES (?,?,?,?,?,?,?)",
                  (did, title, description, json.dumps(widgets or []), time_filter, now, now))
    return get_dashboard(did)

def update_dashboard(dash_id, title=None, description=None, widgets=None, time_filter=None):
    now = time.time()
    with _conn() as c:
        row = c.execute("SELECT * FROM dashboards WHERE id=?", (dash_id,)).fetchone()
        if not row: return None
        c.execute("""UPDATE dashboards SET
            title=?, description=?, widgets=?, time_filter=?, updated_at=?
            WHERE id=?""",
            (title if title is not None else row["title"],
             description if description is not None else row["description"],
             json.dumps(widgets) if widgets is not None else row["widgets"],
             time_filter if time_filter is not None else row["time_filter"],
             now, dash_id))
    return get_dashboard(dash_id)

def delete_dashboard(dash_id):
    with _conn() as c:
        c.execute("DELETE FROM dashboards WHERE id=?", (dash_id,))

init_db()
