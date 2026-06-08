"""
custom_queries.py — Run OpenSearch queries for each visualization type.
"""
from watchtower_client import _os_search, _to_epoch_ms
from datetime import datetime, timezone, timedelta
import time

INDEX_ALIASES = {
    "watchvault-alerts-*":  "watchvault-alerts-*",
    "watchvault-events-*":  "watchvault-events-*",
    "watchvault-vulnerability-*": "watchvault-vulnerability-*",
}

def _time_bounds(time_filter="24h"):
    now = datetime.now(timezone.utc)
    deltas = {"1h": 1, "6h": 6, "12h": 12, "24h": 24, "7d": 168, "30d": 720}
    hours = deltas.get(time_filter, 24)
    start = now - timedelta(hours=hours)
    return int(start.timestamp() * 1000), int(now.timestamp() * 1000)

def _base_query(cfg, start_ms, end_ms):
    must = [{"range": {"timestamp": {"gte": start_ms, "lte": end_ms}}}]
    if cfg.get("min_level"):
        must.append({"range": {"rule_level": {"gte": int(cfg["min_level"])}}})
    if cfg.get("agent_id"):
        must.append({"term": {"agent_id": cfg["agent_id"]}})
    if cfg.get("rule_group"):
        must.append({"bool": {"should": [
            {"term": {"rule_groups.keyword": cfg["rule_group"]}},
            {"term": {"rule_groups": cfg["rule_group"]}},
        ], "minimum_should_match": 1}})
    return {"bool": {"must": must}}

def run_metric(datasource, cfg, time_filter="24h"):
    start_ms, end_ms = _time_bounds(time_filter)
    agg_type = cfg.get("aggregation", "count")
    field = cfg.get("field", "rule_level")
    query = _base_query(cfg, start_ms, end_ms)
    body = {"size": 0, "query": query}
    if agg_type == "count":
        body["aggs"] = {}
    else:
        body["aggs"] = {"metric": {agg_type: {"field": field}}}
    res = _os_search(datasource, body)
    total = (res.get("hits") or {}).get("total") or {}
    count = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    if agg_type == "count":
        return {"value": count, "label": "Total"}
    val = ((res.get("aggregations") or {}).get("metric") or {}).get("value")
    return {"value": round(val, 2) if val is not None else 0, "label": agg_type.upper() + " of " + field}

def run_area(datasource, cfg, time_filter="24h"):
    start_ms, end_ms = _time_bounds(time_filter)
    intervals = {"1h": "1h", "6h": "3h", "12h": "6h", "24h": "1h", "7d": "1d", "30d": "1d"}
    interval = cfg.get("interval") or intervals.get(time_filter, "1h")
    query = _base_query(cfg, start_ms, end_ms)
    aggs = {"by_time": {"date_histogram": {"field": "timestamp", "fixed_interval": interval, "min_doc_count": 0,
                "extended_bounds": {"min": start_ms, "max": end_ms}}}}
    split_field = cfg.get("split_by")
    if split_field:
        aggs["by_time"]["aggs"] = {"by_split": {"terms": {"field": split_field, "size": 5}}}
    body = {"size": 0, "query": query, "aggs": aggs}
    res = _os_search(datasource, body)
    buckets = ((res.get("aggregations") or {}).get("by_time") or {}).get("buckets", [])
    if split_field:
        series = {}
        for b in buckets:
            ts = b.get("key")
            for sb in (b.get("by_split") or {}).get("buckets", []):
                k = str(sb.get("key", "—"))
                series.setdefault(k, []).append({"ts": ts, "count": sb.get("doc_count", 0)})
        return {"series": [{"name": k, "data": v} for k, v in series.items()]}
    return {"series": [{"name": "Events", "data": [{"ts": b.get("key"), "count": b.get("doc_count", 0)} for b in buckets]}]}

def run_bar(datasource, cfg, time_filter="24h"):
    start_ms, end_ms = _time_bounds(time_filter)
    field = cfg.get("field", "rule_groups")
    size = int(cfg.get("size", 10))
    query = _base_query(cfg, start_ms, end_ms)
    # Use bare field for keyword-mapped arrays (rule_groups, agent_id are keyword type in OS mapping)
    # Only append .keyword for text fields that have a keyword sub-field
    kw_field = field  # default: use as-is (most fields in WatchVault are keyword)
    body = {"size": 0, "query": query, "aggs": {"by_field": {"terms": {"field": kw_field, "size": size}}}}
    res = _os_search(datasource, body)
    buckets = ((res.get("aggregations") or {}).get("by_field") or {}).get("buckets", [])
    return {"bars": [{"label": str(b.get("key","—")), "count": b.get("doc_count", 0)} for b in buckets]}

def run_pie(datasource, cfg, time_filter="24h"):
    # Same as bar but returned as slices
    result = run_bar(datasource, cfg, time_filter)
    return {"slices": [{"label": b["label"], "value": b["count"]} for b in result.get("bars", [])]}

def run_table(datasource, cfg, time_filter="24h"):
    start_ms, end_ms = _time_bounds(time_filter)
    fields = cfg.get("fields") or ["timestamp","rule_level","rule_description","agent_id"]
    size = int(cfg.get("size", 10))
    query = _base_query(cfg, start_ms, end_ms)
    body = {"size": size, "query": query, "sort": [{"timestamp": {"order": "desc"}}], "_source": fields}
    res = _os_search(datasource, body)
    hits = (res.get("hits") or {}).get("hits", [])
    rows = []
    for h in hits:
        src = h.get("_source") or {}
        rows.append({f: src.get(f) for f in fields})
    return {"columns": fields, "rows": rows}

def run_markdown(datasource, cfg, time_filter="24h"):
    return {"content": cfg.get("content", "")}

RUNNERS = {
    "metric": run_metric,
    "area": run_area,
    "bar": run_bar,
    "pie": run_pie,
    "table": run_table,
    "markdown": run_markdown,
}

def run_visualization(viz_type, datasource, config, time_filter="24h"):
    runner = RUNNERS.get(viz_type)
    if not runner:
        return {"error": f"Unknown viz type: {viz_type}"}
    try:
        return runner(datasource, config, time_filter)
    except Exception as e:
        return {"error": str(e)}
