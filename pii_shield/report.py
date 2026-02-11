"""HTML report generator for pii-shield scan results."""

import os
import tempfile
import webbrowser
from datetime import datetime, timezone


def _base_style():
    return """
    :root {
        --bg: #0d1117; --card: #161b22; --border: #30363d;
        --text: #e6edf3; --muted: #8b949e;
        --green: #3fb950; --red: #f85149; --blue: #58a6ff;
        --purple: #bc8cff; --orange: #d29922; --yellow: #e3b341;
    }
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
        font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;
        background:var(--bg); color:var(--text); line-height:1.6;
        padding:2rem; max-width:1100px; margin:0 auto;
    }
    .header { text-align:center; margin-bottom:2rem; padding-bottom:1.5rem; border-bottom:1px solid var(--border); }
    .header h1 { font-size:1.8rem; margin-bottom:0.3rem; }
    .header .subtitle { color:var(--muted); font-size:0.95rem; }
    .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:1rem; margin-bottom:2rem; }
    .card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1.2rem; }
    .card .label { color:var(--muted); font-size:0.8rem; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:0.3rem; }
    .card .value { font-size:1.5rem; font-weight:600; }
    .card .value.pass { color:var(--green); }
    .card .value.fail { color:var(--red); }
    .card .value.warn { color:var(--orange); }
    .section { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin-bottom:1.5rem; }
    .section h2 { font-size:1.1rem; margin-bottom:1rem; padding-bottom:0.5rem; border-bottom:1px solid var(--border); }
    table { width:100%; border-collapse:collapse; font-size:0.85rem; }
    th { text-align:left; color:var(--muted); font-weight:500; padding:0.5rem 0.8rem; border-bottom:1px solid var(--border); font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; }
    td { padding:0.5rem 0.8rem; border-bottom:1px solid var(--border); }
    tr:last-child td { border-bottom:none; }
    tr:hover { background:rgba(88,166,255,0.04); }
    .badge { display:inline-block; padding:0.15rem 0.5rem; border-radius:4px; font-size:0.72rem; font-weight:500; }
    .conf-high { background:rgba(248,81,73,0.15); color:var(--red); }
    .conf-med { background:rgba(210,153,34,0.15); color:var(--orange); }
    .conf-low { background:rgba(63,185,80,0.15); color:var(--green); }
    .mono { font-family:'SF Mono',Monaco,Consolas,monospace; font-size:0.82rem; }
    .context { color:var(--muted); font-size:0.8rem; font-style:italic; }
    .bar-container { background:var(--bg); border-radius:4px; height:8px; width:100%; }
    .bar { height:8px; border-radius:4px; }
    .footer { text-align:center; color:var(--muted); font-size:0.8rem; margin-top:2rem; padding-top:1rem; border-top:1px solid var(--border); }
    .footer a { color:var(--blue); text-decoration:none; }
    """


def generate_html(results):
    """Generate HTML report from scan results.

    Args:
        results: List of ScanResult objects

    Returns:
        HTML string
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_files = len(results)
    total_matches = sum(len(r.matches) for r in results)
    files_with_pii = sum(1 for r in results if r.matches)

    # Aggregate by type
    type_counts = {}
    for r in results:
        for m in r.matches:
            type_counts[m.type] = type_counts.get(m.type, 0) + 1

    status = "CLEAN" if total_matches == 0 else f"{total_matches} FOUND"
    status_class = "pass" if total_matches == 0 else "fail"

    # Type summary cards
    type_html = ""
    for ptype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        type_html += f'<div class="card"><div class="label">{ptype}</div><div class="value warn">{count}</div></div>'

    # Match rows
    rows_html = ""
    for r in results:
        for m in r.matches:
            conf_class = "conf-high" if m.confidence >= 90 else "conf-med" if m.confidence >= 70 else "conf-low"
            masked = m.value[:3] + "***" + m.value[-2:] if len(m.value) > 5 else "***"
            rows_html += f"""
            <tr>
                <td class="mono">{r.file}</td>
                <td><span class="badge {conf_class}">{m.type}</span></td>
                <td class="mono">{masked}</td>
                <td><span class="badge {conf_class}">{m.confidence}%</span></td>
                <td>Line {m.line}</td>
                <td class="context">{m.context[:60]}...</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>pii-shield Scan Report</title>
<style>{_base_style()}</style>
</head>
<body>

<div class="header">
    <h1>pii-shield Scan Report</h1>
    <div class="subtitle">PII Detection Results &mdash; {now}</div>
</div>

<div class="cards">
    <div class="card">
        <div class="label">Status</div>
        <div class="value {status_class}">{status}</div>
    </div>
    <div class="card">
        <div class="label">Files Scanned</div>
        <div class="value">{total_files}</div>
    </div>
    <div class="card">
        <div class="label">Files with PII</div>
        <div class="value {"fail" if files_with_pii else "pass"}">{files_with_pii}</div>
    </div>
    <div class="card">
        <div class="label">Total Findings</div>
        <div class="value {"fail" if total_matches else "pass"}">{total_matches}</div>
    </div>
</div>

{"<div class='section'><h2>Findings by Type</h2><div class='cards'>" + type_html + "</div></div>" if type_counts else ""}

<div class="section">
    <h2>Detailed Findings</h2>
    {"<table><thead><tr><th>File</th><th>Type</th><th>Value</th><th>Confidence</th><th>Location</th><th>Context</th></tr></thead><tbody>" + rows_html + "</tbody></table>" if rows_html else "<p style='color:var(--green);'>No PII detected. All clear.</p>"}
</div>

<div class="footer">
    <p>Generated by <a href="https://pypi.org/project/pii-shield/">pii-shield</a> &mdash; Context-aware PII detection</p>
</div>

</body>
</html>"""
    return html


def export_html(results, output_path=None):
    """Generate and save HTML report, return file path."""
    html = generate_html(results)
    if not output_path:
        output_path = os.path.join(tempfile.gettempdir(), "pii-shield-report.html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
