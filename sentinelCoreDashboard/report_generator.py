"""
report_generator.py — Generate PDF security reports for Sentinel SIEM.
Requires: pip install weasyprint  (optional — falls back to HTML if unavailable)
"""
import os
import io
from datetime import datetime, timezone, timedelta
from typing import Optional


def _html_report(data: dict, report_type: str, time_range_label: str) -> str:
    """Build an HTML report that WeasyPrint converts to PDF."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary  = data.get("summary", {})
    alerts   = data.get("top_alerts", [])
    agents   = data.get("agents", [])
    vulns    = data.get("top_vulns", [])
    by_sev   = data.get("by_severity", {})

    # Severity breakdown bars
    def sev_bar(label, count, color, total):
        pct = round(count / max(total, 1) * 100)
        return f"""<div style="margin:6px 0">
          <span style="display:inline-block;width:80px;font-size:11px;color:#555">{label}</span>
          <div style="display:inline-block;background:#eee;border-radius:4px;width:200px;vertical-align:middle">
            <div style="background:{color};height:14px;border-radius:4px;width:{pct}%"></div>
          </div>
          <span style="font-size:11px;color:#333;margin-left:8px">{count}</span>
        </div>"""

    total_alerts = summary.get("total_alerts", 0)
    crit = by_sev.get("CRITICAL", 0) + by_sev.get("critical", 0)
    high = by_sev.get("HIGH", 0) + by_sev.get("high", 0)
    med  = by_sev.get("MEDIUM", 0) + by_sev.get("medium", 0)
    low  = by_sev.get("LOW", 0) + by_sev.get("low", 0)

    # Top alerts table
    alert_rows = "".join(
        f"<tr style='background:{'#fff' if i%2==0 else '#f9f9f9'}'>"
        f"<td style='padding:6px 10px;font-size:11px'>{a.get('rule_id','&mdash;')}</td>"
        f"<td style='padding:6px 10px;font-size:11px'>{str(a.get('description','&mdash;'))[:80]}</td>"
        f"<td style='padding:6px 10px;font-size:11px;text-align:center'>"
        f"<span style='background:{'#d32f2f' if int(a.get('level',0))>=12 else '#e65100' if int(a.get('level',0))>=8 else '#f9a825'};color:#fff;padding:2px 8px;border-radius:10px;font-size:10px'>"
        f"{int(a.get('level',0))}</span></td>"
        f"<td style='padding:6px 10px;font-size:11px;text-align:right'>{a.get('count',0):,}</td>"
        f"</tr>"
        for i, a in enumerate(alerts[:15])
    )

    # Agents table
    agent_rows = "".join(
        f"<tr style='background:{'#fff' if i%2==0 else '#f9f9f9'}'>"
        f"<td style='padding:6px 10px;font-size:11px'>{ag.get('name') or ag.get('hostname','&mdash;')}</td>"
        f"<td style='padding:6px 10px;font-size:11px'>"
        f"<span style='background:{'#388e3c' if ag.get('status')=='active' else '#c62828'};color:#fff;padding:2px 8px;border-radius:10px;font-size:10px'>"
        f"{ag.get('status','&mdash;')}</span></td>"
        f"<td style='padding:6px 10px;font-size:11px'>{ag.get('os_label','&mdash;')}</td>"
        f"<td style='padding:6px 10px;font-size:11px;text-align:right'>{ag.get('alert_count',0):,}</td>"
        f"</tr>"
        for i, ag in enumerate(agents[:20])
    )

    # Vulnerability section
    vuln_section = ""
    if vulns:
        vuln_rows = "".join(
            f"<tr style='background:{'#fff' if i%2==0 else '#f9f9f9'}'>"
            f"<td style='padding:6px 10px;font-size:11px;font-weight:bold'>{v.get('cve_id','&mdash;')}</td>"
            f"<td style='padding:6px 10px;font-size:11px'>{v.get('package_name','&mdash;')} {v.get('package_version','')}</td>"
            f"<td style='padding:6px 10px;font-size:11px'>"
            f"<span style='background:{'#d32f2f' if v.get('severity','').upper()=='CRITICAL' else '#e65100' if v.get('severity','').upper()=='HIGH' else '#f9a825'};color:#fff;padding:2px 8px;border-radius:10px;font-size:10px'>"
            f"{v.get('severity','&mdash;')}</span></td>"
            f"<td style='padding:6px 10px;font-size:11px;text-align:right'>{v.get('cvss_score','&mdash;')}</td>"
            f"</tr>"
            for i, v in enumerate(vulns[:10])
        )
        vuln_section = f"""
        <h2 style="color:#1565c0;border-bottom:2px solid #1565c0;padding-bottom:6px;margin-top:32px">
          Vulnerability Summary
        </h2>
        <table style="width:100%;border-collapse:collapse;margin-top:12px">
          <thead><tr style="background:#1565c0;color:#fff">
            <th style="padding:8px 10px;text-align:left;font-size:11px">CVE ID</th>
            <th style="padding:8px 10px;text-align:left;font-size:11px">Package</th>
            <th style="padding:8px 10px;text-align:left;font-size:11px">Severity</th>
            <th style="padding:8px 10px;text-align:right;font-size:11px">CVSS</th>
          </tr></thead>
          <tbody>{vuln_rows}</tbody>
        </table>"""

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body {{ font-family: Arial, Helvetica, sans-serif; color: #333; margin: 0; padding: 0; }}
  @page {{ margin: 20mm; }}
</style>
</head>
<body>
  <!-- Header -->
  <div style="background:linear-gradient(135deg,#0d1b2a,#1565c0);color:#fff;padding:28px 32px;border-radius:0 0 8px 8px">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <h1 style="margin:0;font-size:22px;letter-spacing:1px">SENTINEL CORE SIEM</h1>
        <p style="margin:4px 0 0;font-size:13px;opacity:0.8">Security Report &mdash; {report_type}</p>
      </div>
      <div style="text-align:right;font-size:11px;opacity:0.8">
        <div>Generated: {now_str}</div>
        <div>Period: {time_range_label}</div>
      </div>
    </div>
  </div>

  <div style="padding:24px 32px">
    <!-- Executive Summary KPIs -->
    <h2 style="color:#1565c0;border-bottom:2px solid #1565c0;padding-bottom:6px">Executive Summary</h2>
    <div style="display:flex;gap:16px;margin:16px 0">
      <div style="flex:1;background:#fff3e0;border-left:4px solid #e65100;padding:14px 18px;border-radius:4px">
        <div style="font-size:28px;font-weight:bold;color:#e65100">{total_alerts:,}</div>
        <div style="font-size:11px;color:#666;text-transform:uppercase">Total Alerts</div>
      </div>
      <div style="flex:1;background:#ffebee;border-left:4px solid #d32f2f;padding:14px 18px;border-radius:4px">
        <div style="font-size:28px;font-weight:bold;color:#d32f2f">{crit + high:,}</div>
        <div style="font-size:11px;color:#666;text-transform:uppercase">Critical + High</div>
      </div>
      <div style="flex:1;background:#e8f5e9;border-left:4px solid #388e3c;padding:14px 18px;border-radius:4px">
        <div style="font-size:28px;font-weight:bold;color:#388e3c">{summary.get('active_agents', 0)}</div>
        <div style="font-size:11px;color:#666;text-transform:uppercase">Active Agents</div>
      </div>
      <div style="flex:1;background:#e3f2fd;border-left:4px solid #1565c0;padding:14px 18px;border-radius:4px">
        <div style="font-size:28px;font-weight:bold;color:#1565c0">{summary.get('unique_cves', 0)}</div>
        <div style="font-size:11px;color:#666;text-transform:uppercase">Unique CVEs</div>
      </div>
    </div>

    <!-- Severity Breakdown -->
    <h2 style="color:#1565c0;border-bottom:2px solid #1565c0;padding-bottom:6px;margin-top:28px">Alert Severity Breakdown</h2>
    <div style="margin:12px 0">
      {sev_bar('Critical', crit, '#d32f2f', total_alerts)}
      {sev_bar('High', high, '#e65100', total_alerts)}
      {sev_bar('Medium', med, '#f9a825', total_alerts)}
      {sev_bar('Low', low, '#388e3c', total_alerts)}
    </div>

    <!-- Top Alerts -->
    <h2 style="color:#1565c0;border-bottom:2px solid #1565c0;padding-bottom:6px;margin-top:28px">Top Alert Rules</h2>
    <table style="width:100%;border-collapse:collapse;margin-top:12px">
      <thead><tr style="background:#1565c0;color:#fff">
        <th style="padding:8px 10px;text-align:left;font-size:11px">Rule ID</th>
        <th style="padding:8px 10px;text-align:left;font-size:11px">Description</th>
        <th style="padding:8px 10px;text-align:center;font-size:11px">Level</th>
        <th style="padding:8px 10px;text-align:right;font-size:11px">Count</th>
      </tr></thead>
      <tbody>{alert_rows or '<tr><td colspan="4" style="padding:12px;text-align:center;color:#999">No alerts in this period</td></tr>'}</tbody>
    </table>

    <!-- Agent Status -->
    <h2 style="color:#1565c0;border-bottom:2px solid #1565c0;padding-bottom:6px;margin-top:28px">Agent Status</h2>
    <table style="width:100%;border-collapse:collapse;margin-top:12px">
      <thead><tr style="background:#1565c0;color:#fff">
        <th style="padding:8px 10px;text-align:left;font-size:11px">Agent Name</th>
        <th style="padding:8px 10px;text-align:left;font-size:11px">Status</th>
        <th style="padding:8px 10px;text-align:left;font-size:11px">OS</th>
        <th style="padding:8px 10px;text-align:right;font-size:11px">Alerts</th>
      </tr></thead>
      <tbody>{agent_rows or '<tr><td colspan="4" style="padding:12px;text-align:center;color:#999">No agents found</td></tr>'}</tbody>
    </table>

    {vuln_section}

    <!-- Footer -->
    <div style="margin-top:40px;padding-top:16px;border-top:1px solid #ddd;font-size:10px;color:#999;text-align:center">
      Sentinel SIEM Security Report &middot; Confidential &middot; Generated {now_str}
    </div>
  </div>
</body>
</html>"""


def generate_pdf(data: dict, report_type: str = "Security Report",
                 time_range_label: str = "Last 30 days") -> Optional[bytes]:
    """Generate PDF bytes from report data. Returns None if WeasyPrint unavailable."""
    try:
        from weasyprint import HTML
        html = _html_report(data, report_type, time_range_label)
        buf = io.BytesIO()
        HTML(string=html).write_pdf(buf)
        return buf.getvalue()
    except ImportError:
        return None
    except Exception as e:
        import logging
        logging.getLogger(__name__).error("PDF generation failed: %s", e)
        return None


def generate_html(data: dict, report_type: str = "Security Report",
                  time_range_label: str = "Last 30 days") -> str:
    """Return HTML report (fallback when WeasyPrint not available)."""
    return _html_report(data, report_type, time_range_label)
