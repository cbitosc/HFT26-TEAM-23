"""Streamlit overview dashboard for the Shadow IT scanner."""

from __future__ import annotations

import html
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import plotly.graph_objects as go
import streamlit as st

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from analyzer import analyze_file, analyze_records
from database import DEFAULT_DB, fetch_analyses
from parser import SAMPLE_PATH, parse_csv_text, parse_json_logs

PRODUCT_NAME = "AI Shadow IT & Agentic Data Exfiltration Scanner"
NAV_ITEMS = ("Overview", "Alerts", "Apps", "Agents", "Upload")
RECENT_LIMIT = 16
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

CHART_FONT = "IBM Plex Sans, Segoe UI, sans-serif"
COLOR = {
    "text": "#c9ced6",
    "muted": "#8b919c",
    "grid": "#2a3038",
    "critical": "#b44545",
    "high": "#c56b4a",
    "medium": "#c4a35a",
    "low": "#6d767f",
    "accent": "#3f8f70",
}

DASHBOARD_CSS = """
<style>
@import url("https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap");

html, body, [class*="css"] {
    font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
}
.stApp {
    background: #14171c;
    color: #c9ced6;
}
header[data-testid="stHeader"] {
    background: #14171c;
    border-bottom: 1px solid #2a3038;
}
#MainMenu, footer, [data-testid="stToolbar"] {
    visibility: hidden;
    height: 0;
}
[data-testid="stSidebar"] {
    background: #101317;
    border-right: 1px solid #2a3038;
}
[data-testid="stSidebar"] > div:first-child {
    padding: 18px 14px 24px 14px;
}
[data-testid="stPlotlyChart"] {
    border: 1px solid #2a3038;
    background: #1a1e25;
    padding: 4px 6px 0 6px;
    margin-bottom: 12px;
}
.block-container {
    padding: 1rem 1.35rem 1.6rem 1.35rem;
    max-width: 1280px;
}
.brand-mark {
    font-size: 11px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: #8b919c;
    margin-bottom: 4px;
}
.brand-name {
    font-size: 15px;
    font-weight: 600;
    color: #e8eaed;
    line-height: 1.3;
    margin-bottom: 18px;
}
.nav-label {
    font-size: 11px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #6d767f;
    margin-bottom: 8px;
}
div[data-testid="stSidebar"] .stRadio > label {
    display: none;
}
div[data-testid="stSidebar"] .stRadio [role="radiogroup"] label {
    background: transparent;
    border: 1px solid transparent;
    padding: 7px 10px;
    margin-bottom: 2px;
    font-size: 13.5px;
    color: #b4bac3;
}
div[data-testid="stSidebar"] .stRadio [role="radiogroup"] label:has(input:checked) {
    background: #1a221f;
    border: 1px solid #2d4a3e;
    color: #d7e6df;
}
.app-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 16px;
    border-bottom: 1px solid #2a3038;
    padding-bottom: 12px;
    margin-bottom: 16px;
}
.app-header h1 {
    margin: 0;
    font-size: 18px;
    font-weight: 600;
    color: #e8eaed;
    letter-spacing: 0;
}
.app-header .section {
    margin: 3px 0 0 0;
    font-size: 12px;
    color: #8b919c;
}
.status-wrap {
    text-align: right;
    font-size: 12px;
    color: #8b919c;
}
.status-live {
    color: #3f8f70;
    font-weight: 500;
}
.status-off {
    color: #c56b4a;
    font-weight: 500;
}
.source-note {
    margin: 0 0 14px 0;
    font-size: 12px;
    color: #8b919c;
}
.metric-row {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin-bottom: 16px;
}
.metric {
    border: 1px solid #2a3038;
    background: #1a1e25;
    padding: 10px 12px 11px 12px;
}
.metric-label {
    font-size: 11px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #8b919c;
}
.metric-value {
    margin-top: 6px;
    font-family: "IBM Plex Mono", "Consolas", monospace;
    font-size: 22px;
    font-weight: 500;
    color: #e8eaed;
    line-height: 1.1;
}
.metric-hint {
    margin-top: 4px;
    font-size: 11px;
    color: #6d767f;
}
.panel {
    border: 1px solid #2a3038;
    background: #1a1e25;
    padding: 12px 12px 8px 12px;
    margin-bottom: 12px;
}
.panel h2 {
    margin: 0 0 8px 0;
    font-size: 13px;
    font-weight: 600;
    color: #d5d8de;
}
.panel-caption {
    margin: -4px 0 8px 0;
    font-size: 11px;
    color: #8b919c;
}
.empty-note {
    border: 1px solid #2a3038;
    background: #1a1e25;
    padding: 18px 16px;
    color: #8b919c;
    font-size: 13px;
}
table.activity {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
}
table.activity th {
    text-align: left;
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: #8b919c;
    border-bottom: 1px solid #2a3038;
    padding: 6px 8px;
    white-space: nowrap;
}
table.activity td {
    border-bottom: 1px solid #232830;
    padding: 7px 8px;
    color: #c9ced6;
    vertical-align: middle;
}
table.activity tr:last-child td {
    border-bottom: none;
}
.mono {
    font-family: "IBM Plex Mono", "Consolas", monospace;
    font-size: 12px;
}
.badge {
    display: inline-block;
    min-width: 58px;
    text-align: center;
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.04em;
    padding: 2px 6px;
    border: 1px solid transparent;
}
.badge-critical { color: #e7c4c4; background: #3a2424; border-color: #5c3232; }
.badge-high { color: #ead3c8; background: #3a2b24; border-color: #5c4032; }
.badge-medium { color: #e6dcbf; background: #322e22; border-color: #534a32; }
.badge-low { color: #c4c8cc; background: #262a2e; border-color: #3a4046; }
@media (max-width: 980px) {
    .metric-row { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .app-header { flex-direction: column; align-items: flex-start; }
    .status-wrap { text-align: left; }
}
@media (max-width: 640px) {
    .metric-row { grid-template-columns: 1fr; }
    table.activity { font-size: 12px; }
}
</style>
"""


def _as_findings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def load_analyses() -> tuple[list[dict[str, Any]], str, bool]:
    """Load stored analyses, or analyze sample traffic without persisting it."""
    rows = []
    if DEFAULT_DB.exists():
        try:
            rows = fetch_analyses(DEFAULT_DB)
        except Exception as exc:
            return [], f"Could not read the audit database: {exc}", False

    if rows:
        return rows, f"Audit store · {len(rows)} analyzed requests", True

    if not SAMPLE_PATH.exists():
        return [], (
            "The audit database is empty and the sample traffic file was not found at "
            f"{SAMPLE_PATH}."
        ), False

    try:
        sample_rows = analyze_file(SAMPLE_PATH, persist=False)
        return sample_rows, f"Sample traffic · {len(sample_rows)} analyzed requests", True
    except Exception as exc:
        return [], f"Could not generate results from sample traffic: {exc}", False


def compute_metrics(rows: list[dict[str, Any]]) -> dict[str, int]:
    ai_calls = sum(1 for row in rows if row.get("is_ai"))
    leaks = sum(len(_as_findings(row.get("findings"))) for row in rows)
    high_risk = sum(1 for row in rows if str(row.get("risk_label") or "").lower() == "high")
    overall = round(sum(_safe_int(row.get("score")) for row in rows) / len(rows)) if rows else 0
    return {
        "total": len(rows),
        "ai_calls": ai_calls,
        "leaks": leaks,
        "high_risk": high_risk,
        "overall": overall,
    }


def row_severity(row: dict[str, Any]) -> str:
    findings = _as_findings(row.get("findings"))
    ranks = [SEVERITY_RANK.get(str(item.get("severity") or "").lower(), 0) for item in findings]
    if ranks:
        best = max(ranks)
        for name, rank in SEVERITY_RANK.items():
            if rank == best:
                return name.title()
    label = str(row.get("risk_label") or "Low")
    return label.title() if label else "Low"


def _chart_layout(title: str, height: int = 280) -> dict[str, Any]:
    return dict(
        title=dict(text=title, font=dict(size=13, color=COLOR["text"], family=CHART_FONT), x=0, xanchor="left"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLOR["muted"], size=12, family=CHART_FONT),
        margin=dict(l=36, r=12, t=42, b=48),
        height=height,
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.22,
            x=0,
            font=dict(size=11, color=COLOR["text"]),
            bgcolor="rgba(0,0,0,0)",
        ),
        xaxis=dict(gridcolor=COLOR["grid"], linecolor=COLOR["grid"], zeroline=False, tickfont=dict(size=11)),
        yaxis=dict(gridcolor=COLOR["grid"], linecolor=COLOR["grid"], zeroline=False, tickfont=dict(size=11), rangemode="tozero"),
        bargap=0.35,
    )


def risk_distribution_chart(rows: list[dict[str, Any]]) -> go.Figure:
    counts = Counter(str(row.get("risk_label") or "Low") for row in rows)
    labels = ["High", "Medium", "Low"]
    values = [counts.get(name, 0) for name in labels]
    colors = [COLOR["high"], COLOR["medium"], COLOR["low"]]
    fig = go.Figure(
        go.Bar(
            x=labels,
            y=values,
            marker_color=colors,
            name="Requests",
            hovertemplate="%{x}: %{y} requests<extra></extra>",
        )
    )
    fig.update_layout(**_chart_layout("Requests by risk label"))
    fig.update_yaxes(title_text="Requests", title_font=dict(size=11, color=COLOR["muted"]))
    fig.update_xaxes(title_text="Risk label", title_font=dict(size=11, color=COLOR["muted"]))
    return fig


def findings_chart(rows: list[dict[str, Any]]) -> go.Figure:
    types = Counter()
    for row in rows:
        for item in _as_findings(row.get("findings")):
            types[str(item.get("type") or "unknown")] += 1
    if not types:
        fig = go.Figure()
        fig.update_layout(**_chart_layout("Findings by type"))
        fig.add_annotation(text="No findings in the current dataset", showarrow=False, font=dict(color=COLOR["muted"]))
        return fig
    labels, values = zip(*types.most_common(8))
    fig = go.Figure(
        go.Bar(
            y=list(labels)[::-1],
            x=list(values)[::-1],
            orientation="h",
            marker_color=COLOR["accent"],
            name="Findings",
            hovertemplate="%{y}: %{x} findings<extra></extra>",
        )
    )
    fig.update_layout(**_chart_layout("Findings by type"))
    fig.update_xaxes(title_text="Count", title_font=dict(size=11, color=COLOR["muted"]))
    fig.update_yaxes(title_text="Finding type", title_font=dict(size=11, color=COLOR["muted"]))
    return fig


def provider_chart(rows: list[dict[str, Any]]) -> go.Figure:
    providers = Counter(
        str(row.get("provider") or "Unknown")
        for row in rows
        if row.get("is_ai")
    )
    if not providers:
        fig = go.Figure()
        fig.update_layout(**_chart_layout("AI calls by provider"))
        fig.add_annotation(text="No AI provider calls in this dataset", showarrow=False, font=dict(color=COLOR["muted"]))
        return fig

    labels, values = zip(*providers.most_common())
    fig = go.Figure(
        go.Pie(
            labels=list(labels),
            values=list(values),
            hole=0.58,
            textinfo="label+percent",
            marker=dict(colors=["#3f8f70", "#6d9e8a", "#c4a35a", "#c56b4a", "#78879a"]),
            hovertemplate="%{label}: %{value} calls<extra></extra>",
        )
    )
    fig.update_layout(**_chart_layout("AI calls by provider"))
    return fig


def render_sidebar(current: str) -> str:
    st.markdown(
        '<div class="brand-mark">Local security console</div>'
        '<div class="brand-name">Shadow IT Scanner</div>'
        '<div class="nav-label">Navigation</div>',
        unsafe_allow_html=True,
    )
    page = st.radio(
        "Section",
        NAV_ITEMS,
        index=NAV_ITEMS.index(current) if current in NAV_ITEMS else 0,
        label_visibility="collapsed",
    )
    st.markdown(
        '<p style="margin-top:18px;font-size:11px;color:#6d767f;line-height:1.45;">'
        "Analyze local traffic logs and review masked scanner findings."
        "</p>",
        unsafe_allow_html=True,
    )
    return page


def render_header(section: str, monitoring: bool, source: str) -> None:
    state_class = "status-live" if monitoring else "status-off"
    state_text = "Monitoring active" if monitoring else "Monitoring unavailable"
    st.markdown(
        f"""
        <div class="app-header">
          <div>
            <h1>{html.escape(PRODUCT_NAME)}</h1>
            <p class="section">{html.escape(section)}</p>
          </div>
          <div class="status-wrap">
            <div class="{state_class}">{state_text}</div>
            <div>{html.escape(source)}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metrics(metrics: dict[str, int]) -> None:
    cards = (
        ("Total AI calls", metrics["ai_calls"], f"{metrics['ai_calls']} of {metrics['total']} requests"),
        ("Total detected leaks", metrics["leaks"], "Finding count across analyzed traffic"),
        ("High-risk requests", metrics["high_risk"], f"{metrics['high_risk']} of {metrics['total']} scored High"),
        ("Overall risk score", metrics["overall"], "Mean of stored request scores"),
    )
    cells = []
    for label, value, hint in cards:
        cells.append(
            "<div class='metric'>"
            f"<div class='metric-label'>{html.escape(label)}</div>"
            f"<div class='metric-value'>{value}</div>"
            f"<div class='metric-hint'>{html.escape(hint)}</div>"
            "</div>"
        )
    st.markdown(f"<div class='metric-row'>{''.join(cells)}</div>", unsafe_allow_html=True)


def render_charts(rows: list[dict[str, Any]]) -> None:
    left, right = st.columns(2, gap="small")
    config = {"displayModeBar": False, "responsive": True}
    with left:
        st.plotly_chart(provider_chart(rows), width="stretch", config=config)
    with right:
        st.plotly_chart(risk_distribution_chart(rows), width="stretch", config=config)


def render_activity_table(rows: list[dict[str, Any]]) -> None:
    st.markdown(
        "<div class='panel'><h2>Recent activity</h2>"
        "<p class='panel-caption'>Newest analyzed requests from the audit store. Finding previews remain masked.</p>",
        unsafe_allow_html=True,
    )
    if not rows:
        st.markdown(
            "<div class='empty-note'>No analyzed requests yet. Run the scanner or add sample traffic to populate this view.</div></div>",
            unsafe_allow_html=True,
        )
        return

    recent = list(reversed(rows[-RECENT_LIMIT:]))
    body = []
    for row in recent:
        severity = row_severity(row)
        badge = f"<span class='badge badge-{html.escape(severity.lower())}'>{html.escape(severity)}</span>"
        findings = _as_findings(row.get("findings"))
        host = html.escape(str(row.get("host") or "unknown-host"))
        path = html.escape(str(row.get("path") or "/"))
        app = html.escape(str(row.get("app") or "unknown"))
        when = html.escape(str(row.get("time") or "—"))
        kind = "AI" if row.get("is_ai") else "Other"
        provider = html.escape(str(row.get("provider") or "—"))
        score = _safe_int(row.get("score"))
        body.append(
            "<tr>"
            f"<td class='mono'>{when}</td>"
            f"<td>{host}{path}</td>"
            f"<td>{app}</td>"
            f"<td>{kind}</td>"
            f"<td>{provider}</td>"
            f"<td>{len(findings)}</td>"
            f"<td>{badge}</td>"
            f"<td class='mono'>{score}</td>"
            "</tr>"
        )
    st.markdown(
        "<table class='activity'>"
        "<thead><tr>"
        "<th>Time</th><th>Destination</th><th>App</th><th>Traffic</th>"
        "<th>Provider</th><th>Findings</th><th>Severity</th><th>Score</th>"
        "</tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table></div>",
        unsafe_allow_html=True,
    )


def _finding_rows(rows: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    return [
        (row, finding)
        for row in rows
        for finding in _as_findings(row.get("findings"))
    ]


def render_alerts(rows: list[dict[str, Any]]) -> None:
    st.markdown(
        "<div class='panel'><h2>Masked leak alerts</h2>"
        "<p class='panel-caption'>Sensitive values are masked by the scanner before they reach this table.</p>",
        unsafe_allow_html=True,
    )
    alerts = _finding_rows(rows)
    if not alerts:
        st.markdown("<div class='empty-note'>No findings in the current dataset.</div></div>", unsafe_allow_html=True)
        return

    body = []
    for row, finding in reversed(alerts[-RECENT_LIMIT:]):
        severity = str(finding.get("severity") or row_severity(row)).title()
        severity_class = severity.lower() if severity.lower() in {"critical", "high", "medium", "low"} else "low"
        badge = f"<span class='badge badge-{severity_class}'>{html.escape(severity)}</span>"
        cells = (
            str(row.get("time") or "—"),
            f"{row.get('host') or 'unknown-host'}{row.get('path') or '/'}",
            str(row.get("app") or "unknown"),
            str(finding.get("type") or "unknown"),
            str(finding.get("preview") or "***"),
        )
        body.append(
            "<tr>"
            f"<td class='mono'>{html.escape(cells[0])}</td>"
            f"<td>{html.escape(cells[1])}</td>"
            f"<td>{html.escape(cells[2])}</td>"
            f"<td>{html.escape(cells[3])}</td>"
            f"<td>{badge}</td>"
            f"<td class='mono'>{html.escape(cells[4])}</td>"
            "</tr>"
        )
    st.markdown(
        "<table class='activity'><thead><tr>"
        "<th>Time</th><th>Destination</th><th>App</th><th>Finding</th><th>Severity</th><th>Masked preview</th>"
        "</tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table></div>",
        unsafe_allow_html=True,
    )


def render_apps(rows: list[dict[str, Any]]) -> None:
    st.markdown("### Application activity")
    apps: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        apps.setdefault(str(row.get("app") or "unknown"), []).append(row)
    if not apps:
        st.info("No application activity to show.")
        return

    summary = []
    for app, app_rows in sorted(apps.items(), key=lambda item: (-len(item[1]), item[0].lower())):
        summary.append(
            {
                "Application": app,
                "Requests": len(app_rows),
                "AI calls": sum(bool(row.get("is_ai")) for row in app_rows),
                "Findings": sum(len(_as_findings(row.get("findings"))) for row in app_rows),
                "Average risk": round(sum(_safe_int(row.get("score")) for row in app_rows) / len(app_rows)),
                "Destinations": ", ".join(sorted({str(row.get("host") or "unknown") for row in app_rows})),
            }
        )
    st.dataframe(summary, width="stretch", hide_index=True)


def render_agents(rows: list[dict[str, Any]]) -> None:
    st.markdown("### Agent activity")
    agent_rows = [
        row for row in rows
        if any(
            str(finding.get("type") or "") in {"risky_agent", "shell_command", "sensitive_file"}
            for finding in _as_findings(row.get("findings"))
        )
        or "agent" in str(row.get("app") or "").lower()
    ]
    if not agent_rows:
        st.info("No agent-related activity or risky agent findings in this dataset.")
        return

    records = []
    for row in reversed(agent_rows):
        findings = _as_findings(row.get("findings"))
        records.append(
            {
                "Time": str(row.get("time") or "—"),
                "Agent / app": str(row.get("app") or "unknown"),
                "Destination": f"{row.get('host') or 'unknown-host'}{row.get('path') or '/'}",
                "Risk": str(row.get("risk_label") or "Low"),
                "Score": _safe_int(row.get("score")),
                "Masked findings": "; ".join(
                    f"{item.get('type') or 'unknown'}: {item.get('preview') or '***'}"
                    for item in findings
                ) or "—",
            }
        )
    st.dataframe(records, width="stretch", hide_index=True)


def _parse_uploaded_log(upload: Any) -> list[dict[str, Any]]:
    text = upload.getvalue().decode("utf-8-sig")
    suffix = Path(upload.name).suffix.lower()
    if suffix == ".csv":
        return parse_csv_text(text)
    if suffix in {".json", ".har"}:
        return parse_json_logs(json.loads(text))
    raise ValueError("Choose a CSV, JSON, or HAR log file.")


def render_upload() -> None:
    st.markdown("### Upload traffic logs")
    st.caption("Supported formats: CSV, JSON, and HAR. Uploaded content is analyzed in memory and is not saved.")
    upload = st.file_uploader("Choose a log file", type=["csv", "json", "har"])
    if upload is None:
        return

    try:
        records = _parse_uploaded_log(upload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        st.error(f"Could not read {upload.name}: {exc}")
        return

    if not records:
        st.warning("No valid traffic records were found in this file.")
        return

    analyzed = analyze_records(records, persist=False)
    st.success(f"Analyzed {len(analyzed)} requests from {upload.name}.")
    render_metrics(compute_metrics(analyzed))
    render_charts(analyzed)
    render_alerts(analyzed)
    with st.expander("Analyzed request activity"):
        render_activity_table(analyzed)


def main() -> None:
    st.set_page_config(
        page_title=PRODUCT_NAME,
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(DASHBOARD_CSS, unsafe_allow_html=True)

    rows, source, monitoring = load_analyses()
    metrics = compute_metrics(rows)

    with st.sidebar:
        page = render_sidebar(st.session_state.get("nav_page", "Overview"))
        st.session_state["nav_page"] = page

    if page != "Overview":
        render_header(page, monitoring, source)
        if page == "Alerts":
            render_alerts(rows)
        elif page == "Apps":
            render_apps(rows)
        elif page == "Agents":
            render_agents(rows)
        else:
            render_upload()
        return

    render_header("Overview", monitoring, source)
    render_metrics(metrics)
    if rows:
        render_charts(rows)
    render_activity_table(rows)


main()
