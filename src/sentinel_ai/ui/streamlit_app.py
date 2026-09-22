"""Streamlit interface backed by SentinelAI services and SQLite data."""

from __future__ import annotations

from dataclasses import asdict
from html import escape
import sqlite3

import pandas as pd
import streamlit as st

from sentinel_ai import config
from sentinel_ai.demo import SIMULATION_SCENARIOS
from sentinel_ai.services import SentinelService


PAGE_NAMES = ("Dashboard", "Activity Monitor", "User Behaviour", "Threat Simulation", "Alert Investigation")
RISK_COLORS = {"Low": "#45d483", "Medium": "#f3c74f", "High": "#ff934f", "Critical": "#ff5d6c"}
RISK_MARKERS = {"Low": "●", "Medium": "●", "High": "●", "Critical": "●"}
SCENARIO_GUIDE = {
    "Normal login": {
        "category": "Baseline control",
        "description": "A routine login from the employee's usual location and known device during learned working hours.",
        "expected": "No deterministic threat rule should fire; the result should remain Low risk.",
    },
    "Unknown-device login": {
        "category": "Single weak signal",
        "description": "A successful login uses a device that is not part of the employee's known-device baseline.",
        "expected": "Unknown-device evidence should appear, but an isolated signal may remain below the alert threshold.",
    },
    "Impossible-travel login": {
        "category": "Location anomaly",
        "description": "Two successful logins occur too far apart for the elapsed travel time.",
        "expected": "Unusual-location and impossible-travel evidence should reinforce one another.",
    },
    "Brute-force attempt": {
        "category": "Credential attack",
        "description": "Multiple failed attempts are followed by a successful login from an unknown device.",
        "expected": "Failed-login and unknown-device signals should produce an escalated risk result.",
    },
    "Bulk download": {
        "category": "Data movement",
        "description": "The employee downloads far more files and data than their normal behaviour indicates.",
        "expected": "Bulk-download and large-download evidence should be visible independently.",
    },
    "Sensitive-file access": {
        "category": "Sensitive access",
        "description": "The employee accesses a resource outside their typical file-sensitivity pattern.",
        "expected": "The accessed sensitivity and the learned baseline should be shown in the evidence.",
    },
    "Privilege escalation": {
        "category": "Privilege change",
        "description": "The account moves from its normal privilege level to administrator access.",
        "expected": "The previous and current privilege levels should be clearly explained.",
    },
    "Combined account compromise": {
        "category": "Multi-signal compromise",
        "description": "A late-night foreign login combines an unknown device, failures, downloads, sensitive access, and privilege escalation.",
        "expected": "Correlated evidence should produce the strongest result, normally Critical and capped at 100.",
    },
    "Legitimate employee travel": {
        "category": "False-positive control",
        "description": "The employee signs in from an approved destination after a physically plausible journey.",
        "expected": "Approved travel should avoid unusual-location and impossible-travel alerts and remain Low risk.",
    },
}


@st.cache_resource
def get_service() -> SentinelService:
    service = SentinelService()
    service.initialize()
    return service


def _apply_theme() -> None:
    st.markdown(
        """
        <style>
        :root { color-scheme: dark; }
        .stApp { background: #07101d; color: #e8eef7; }
        .block-container { max-width: 1480px; padding-top: 1.7rem; padding-bottom: 3rem; }
        [data-testid="stSidebar"] { background: #0b1625; border-right: 1px solid #203149; }
        [data-testid="stSidebar"] .block-container { padding-top: 1.5rem; }
        [data-testid="stSidebar"] [role="radiogroup"] label { padding: .42rem .55rem; border-radius: 8px; }
        [data-testid="stSidebar"] [role="radiogroup"] label:hover { background: #13253b; }
        [data-testid="stMetric"] { background: #0e1c2e; border: 1px solid #223650; border-radius: 12px; padding: 14px 16px; }
        [data-testid="stMetricLabel"] { color: #9fb1c8; letter-spacing: .02em; }
        [data-testid="stMetricValue"] { color: #f5f8fc; }
        h1, h2, h3 { color: #f5f8fc; letter-spacing: -.02em; }
        p, label, [data-testid="stCaptionContainer"] { color: #c0ccdc; }
        .sentinel-hero { background: linear-gradient(115deg, #0d2038 0%, #0b1829 70%); border: 1px solid #24446a; border-radius: 16px; padding: 19px 23px; margin-bottom: 22px; }
        .sentinel-brand { color: #67a7ff; font-size: .72rem; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
        .sentinel-hero h1 { margin: .12rem 0 .18rem; font-size: 2rem; }
        .sentinel-hero p { color: #aebdd0; margin: 0; }
        .sentinel-subtitle { color: #9fb1c8; margin-top: -.65rem; margin-bottom: 1.35rem; }
        .status-card, .scenario-card, .evidence-card { background: #0e1c2e; border: 1px solid #223650; border-radius: 12px; padding: 14px 16px; margin: 8px 0 16px; }
        .status-card { border-left: 4px solid #398cff; }
        .scenario-card { border-left: 4px solid #67a7ff; }
        .scenario-card strong { color: #f5f8fc; }
        .scenario-card small { color: #67a7ff; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; }
        .risk-pill { display: inline-block; border: 1px solid currentColor; border-radius: 999px; padding: 2px 10px; font-size: .86rem; font-weight: 800; }
        .risk-low { color: #45d483; }
        .risk-medium { color: #f3c74f; }
        .risk-high { color: #ff934f; }
        .risk-critical { color: #ff5d6c; }
        .sidebar-status { background: #0e1c2e; border: 1px solid #223650; border-radius: 10px; padding: 10px 12px; font-size: .82rem; line-height: 1.85; color: #b9c7d8; }
        .status-dot { color: #45d483; margin-right: 6px; }
        .muted { color: #8fa2b9; }
        div[data-testid="stDataFrame"] { border: 1px solid #223650; border-radius: 10px; overflow: hidden; }
        .stButton > button { min-height: 2.65rem; border-radius: 8px; border: 1px solid #398cff; font-weight: 700; }
        div[data-testid="stExpander"] { border-color: #223650; background: #0b1727; }
        hr { border-color: #203149; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _frame(rows: list[dict[str, object]]) -> pd.DataFrame:
    frame = pd.DataFrame(rows)
    if "timestamp" in frame.columns:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    if "created_at" in frame.columns:
        frame["created_at"] = pd.to_datetime(frame["created_at"], utc=True)
    return frame


def _risk_badge(level: str) -> str:
    safe_level = level if level in RISK_COLORS else "Low"
    return f'<span class="risk-pill risk-{safe_level.lower()}">{escape(safe_level)}</span>'


def _page_header(title: str, subtitle: str) -> None:
    st.markdown(
        f'<div class="sentinel-hero"><div class="sentinel-brand">SentinelAI · Explainable Threat Detection</div>'
        f'<h1>{escape(title)}</h1><p>{escape(subtitle)}</p></div>',
        unsafe_allow_html=True,
    )


def _risk_display(level: object) -> str:
    value = str(level) if level in RISK_COLORS else "Low"
    return f"{RISK_MARKERS[value]} {value}"


def _friendly_table(frame: pd.DataFrame, labels: dict[str, str]) -> pd.DataFrame:
    result = frame.rename(columns=labels).copy()
    risk_column = labels.get("risk_level", "Risk Level")
    if risk_column in result.columns:
        result[risk_column] = result[risk_column].map(_risk_display)
    return result


def _rules_table(rules: object) -> pd.DataFrame:
    frame = pd.DataFrame(rules)
    if frame.empty:
        return frame
    return frame.rename(
        columns={
            "rule_name": "Reason Code",
            "contribution": "Score Added",
            "reason": "Why It Triggered",
            "observed_value": "Observed",
            "expected_value": "Expected",
        }
    )


def _model_status_notice(status: str) -> None:
    if status != "ready":
        st.warning("AI anomaly scoring is currently unavailable. Results are using deterministic rules and context only.", icon="⚠️")


def _sidebar_status(service: SentinelService) -> None:
    events = service.event_rows()
    alerts = service.alert_rows()
    active = sum(alert.get("status") not in {"Resolved", "False Positive"} for alert in alerts)
    database_status = "Ready" if events else "Empty"
    model_color = "#45d483" if service.model_status == "ready" else "#f3c74f"
    st.markdown(
        '<div class="sidebar-status">'
        f'<div><span class="status-dot">●</span> Database <strong>{database_status}</strong></div>'
        f'<div><span style="color:{model_color};margin-right:6px">●</span> Model <strong>{escape(service.model_status)}</strong></div>'
        f'<div>Activity events <strong style="float:right">{len(events):,}</strong></div>'
        f'<div>Active alerts <strong style="float:right">{active:,}</strong></div>'
        '</div>',
        unsafe_allow_html=True,
    )


def render_dashboard(service: SentinelService) -> None:
    _page_header("Security Operations Dashboard", "A concise view of behavioural risk, active investigations, and emerging threats.")
    _model_status_notice(service.model_status)
    events = _frame(service.event_rows())
    detections = _frame(service.detection_rows())
    alerts = _frame(service.alert_rows())

    if events.empty:
        st.info("The SentinelAI database is initialized but contains no activity. Use the sidebar reseed action to load the deterministic demo.", icon="ℹ️")
        return

    active_alerts = alerts[~alerts["status"].isin(["Resolved", "False Positive"])] if not alerts.empty else alerts
    high_critical = detections[detections["risk_level"].isin(["High", "Critical"])] if not detections.empty else detections
    columns = st.columns(4)
    columns[0].metric("Activity Events", f"{len(events):,}")
    columns[1].metric("Active alerts", f"{len(active_alerts):,}")
    columns[2].metric("High + Critical", f"{len(high_critical):,}")
    columns[3].metric("Average Risk", f"{detections['final_risk_score'].mean():.1f} / 100" if not detections.empty else "0.0 / 100")
    st.caption("Risk scores combine traceable security rules, Isolation Forest anomaly rank, and contextual correlation. They are not attack probabilities.")

    left, right = st.columns(2)
    with left:
        st.subheader("Threat Trend")
        if detections.empty:
            st.info("No detection results are available yet.")
        else:
            trend = detections.assign(day=detections["timestamp"].dt.date).groupby("day").agg(Alerts=("final_risk_score", lambda values: int((values >= config.ALERT_MINIMUM_SCORE).sum())), **{"Average Risk": ("final_risk_score", "mean")})
            st.line_chart(trend, color=["#ff5d6c", "#398cff"], height=300)
    with right:
        st.subheader("Risk Distribution")
        if detections.empty:
            st.info("No detection results are available yet.")
        else:
            order = ["Low", "Medium", "High", "Critical"]
            distribution = detections["risk_level"].value_counts().reindex(order, fill_value=0)
            chart = pd.DataFrame([distribution.to_dict()], index=["Detected events"])
            st.bar_chart(chart, horizontal=True, color=[RISK_COLORS[level] for level in order], height=300)

    left, right = st.columns(2)
    with left:
        st.subheader("Recent Alerts")
        if alerts.empty:
            st.success("No alerts have been generated.", icon="✅")
        else:
            recent = _friendly_table(
                alerts[["created_at", "employee_name", "title", "risk_score", "risk_level", "status"]].head(8),
                {"created_at": "Created", "employee_name": "Employee", "title": "Primary Reason", "risk_score": "Risk Score", "risk_level": "Risk Level", "status": "Status"},
            )
            st.dataframe(recent, hide_index=True, width="stretch", column_config={"Risk Score": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.1f")})
    with right:
        st.subheader("Top High-Risk Users")
        if detections.empty:
            st.info("No user risk history yet.")
        else:
            users = detections.groupby(["employee_id", "employee_name"], as_index=False).agg(max_risk=("final_risk_score", "max"), average_risk=("final_risk_score", "mean"), events=("event_id", "count")).sort_values("max_risk", ascending=False).head(8)
            users = _friendly_table(users, {"employee_id": "Employee ID", "employee_name": "Employee", "max_risk": "Peak Risk", "average_risk": "Average Risk", "events": "Events"})
            st.dataframe(users, hide_index=True, width="stretch", column_config={"Peak Risk": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.1f")})


def render_activity_monitor(service: SentinelService) -> None:
    _page_header("Activity Monitor", "Search employee activity, isolate risk signals, and inspect exactly why an event received its score.")
    _model_status_notice(service.model_status)
    events = _frame(service.event_rows())
    if events.empty:
        st.info("No activity events are available. Initialize or reseed the deterministic demo from the sidebar.", icon="ℹ️")
        return
    events["final_risk_score"] = events["final_risk_score"].fillna(0.0)
    events["risk_level"] = events["risk_level"].fillna("Low")
    with st.container(border=True):
        st.markdown("#### Find activity")
        search = st.text_input("Search events", placeholder="Employee, city, device, file, or scenario…")
        filter_columns = st.columns(4)
        employee = filter_columns[0].selectbox("Employee", ["All employees"] + sorted(events["employee_name"].unique().tolist()))
        department = filter_columns[1].selectbox("Department", ["All departments"] + sorted(events["department"].unique().tolist()))
        risk = filter_columns[2].selectbox("Risk level", ["All risk levels", "Low", "Medium", "High", "Critical"])
        activity = filter_columns[3].selectbox("Activity type", ["All activity types"] + sorted(events["activity_type"].unique().tolist()))
        available_dates = events["timestamp"].dt.date
        selected_dates = st.date_input("Date range", value=(available_dates.min(), available_dates.max()), min_value=available_dates.min(), max_value=available_dates.max())

    filtered = events.copy()
    if employee != "All employees": filtered = filtered[filtered["employee_name"] == employee]
    if department != "All departments": filtered = filtered[filtered["department"] == department]
    if risk != "All risk levels": filtered = filtered[filtered["risk_level"] == risk]
    if activity != "All activity types": filtered = filtered[filtered["activity_type"] == activity]
    if isinstance(selected_dates, tuple) and len(selected_dates) == 2:
        filtered = filtered[(filtered["timestamp"].dt.date >= selected_dates[0]) & (filtered["timestamp"].dt.date <= selected_dates[1])]
    if search:
        searchable = filtered[["employee_name", "city", "country", "device_id", "file_name", "scenario"]].fillna("").astype(str).agg(" ".join, axis=1)
        filtered = filtered[searchable.str.contains(search, case=False, regex=False)]

    st.caption(f"Showing {len(filtered):,} of {len(events):,} activity events")
    if filtered.empty:
        st.info("No events match the current search and filters. Try widening the date range or clearing a filter.", icon="🔎")
        return

    display_columns = ["timestamp", "employee_name", "department", "activity_type", "city", "scenario", "final_risk_score", "risk_level"]
    display = _friendly_table(
        filtered[display_columns],
        {"timestamp": "Time (UTC)", "employee_name": "Employee", "department": "Department", "activity_type": "Activity", "city": "Location", "scenario": "Scenario", "final_risk_score": "Risk Score", "risk_level": "Risk Level"},
    )
    st.dataframe(display, hide_index=True, width="stretch", height=410, column_config={"Risk Score": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.1f")})

    selected_id = st.selectbox("Inspect an event", filtered["event_id"].tolist(), format_func=lambda value: f"{value} · {filtered.loc[filtered['event_id'] == value, 'employee_name'].iloc[0]}")
    row = filtered[filtered["event_id"] == selected_id].iloc[0].to_dict()
    st.subheader("Event Detail")
    summary = st.columns(4)
    summary[0].metric("Risk Score", f"{float(row.get('final_risk_score', 0)):.1f} / 100")
    summary[1].markdown(f"**Risk Level**<br>{_risk_badge(str(row.get('risk_level', 'Low')))}", unsafe_allow_html=True)
    summary[2].metric("Rule Contribution", f"{float(row.get('rule_contribution') or 0):.1f}")
    summary[3].metric("AI Contribution", f"{float(row.get('ai_contribution') or 0):.1f}")
    explanation_tab, context_tab, features_tab = st.tabs(("Why this score", "Event context", "Model features"))
    with explanation_tab:
        st.write(row.get("explanation") or "No explanation is available for this event.")
        evidence = _rules_table(row.get("triggered_rules", []))
        if evidence.empty:
            st.success("No deterministic threat rule fired for this event.", icon="✅")
        else:
            st.dataframe(evidence, hide_index=True, width="stretch")
        if row.get("recommended_response"):
            st.info(f"Recommended response: {row['recommended_response']}")
    with context_tab:
        context = {
            "Event ID": row.get("event_id"), "Time (UTC)": str(row.get("timestamp")), "Employee": row.get("employee_name"),
            "Department": row.get("department"), "Activity": row.get("activity_type"), "Scenario": row.get("scenario"),
            "Location": f"{row.get('city')}, {row.get('country')}", "Device": row.get("device_id"),
            "File": row.get("file_name") or "None", "File sensitivity": row.get("file_sensitivity"),
        }
        context_rows = [(field, str(value)) for field, value in context.items()]
        st.dataframe(pd.DataFrame(context_rows, columns=["Field", "Value"]), hide_index=True, width="stretch")
    with features_tab:
        feature_values = row.get("feature_values") or {}
        if feature_values:
            feature_frame = pd.DataFrame(feature_values.items(), columns=["Feature", "Value"])
            feature_frame["Feature"] = feature_frame["Feature"].str.replace("_", " ").str.title()
            st.dataframe(feature_frame, hide_index=True, width="stretch")
        else:
            st.info("Model features are not available for this event.")


def render_user_behaviour(service: SentinelService) -> None:
    _page_header("User Behaviour", "Compare each employee's learned normal baseline with their observed activity and recent deviations.")
    _model_status_notice(service.model_status)
    employees = service.employees()
    if not employees:
        st.info("No employees are available. Initialize or reseed the deterministic demo from the sidebar.", icon="ℹ️")
        return
    employee = st.selectbox("Choose an employee", employees, index=None, placeholder="Select an employee to inspect…", format_func=lambda item: f"{item.employee_name} · {item.department}")
    if employee is None:
        st.info("Select an employee to view their normal baseline and observed activity.", icon="👤")
        return
    profile = service.database.get_profile(employee.employee_id)
    if profile is None:
        st.warning("This employee does not have enough historical normal activity to build a baseline yet.", icon="⚠️")
        return
    st.markdown(
        f'<div class="status-card"><strong>{escape(employee.employee_name)}</strong> · {escape(employee.department)}<br>'
        f'<span class="muted">{escape(employee.employee_id)} · Home: {escape(employee.home_city)}, {escape(employee.home_country)}</span></div>',
        unsafe_allow_html=True,
    )
    st.subheader("Normal Baseline")
    profile_columns = st.columns(5)
    profile_columns[0].metric("Normal Login Hours", f"{profile.normal_login_start:.1f}–{profile.normal_login_end:.1f}")
    profile_columns[1].metric("Usual Location", ", ".join(profile.usual_cities))
    profile_columns[2].metric("Average Downloads", f"{profile.average_download_count:.1f} files")
    profile_columns[3].metric("Average File Size", f"{profile.average_download_size_mb:.1f} MB")
    profile_columns[4].metric("Normal Privilege", profile.normal_privilege)
    detail_left, detail_right = st.columns(2)
    with detail_left:
        st.markdown("**Known devices**")
        st.write(" · ".join(profile.known_devices) or "No known devices")
    with detail_right:
        st.markdown("**Typical file access**")
        st.write(" · ".join(profile.typical_file_sensitivity) or "No established sensitivity pattern")
    st.caption(f"Baseline confidence: {profile.confidence * 100:.0f}% from {profile.history_event_count} historical normal events · Average failed logins: {profile.average_failed_login_count:.2f}")

    detections = _frame(service.detection_rows(employee.employee_id))
    st.divider()
    st.subheader("Observed Activity")
    if detections.empty:
        st.info("No observed activity is available for this employee.")
        return
    left, right = st.columns((2, 1))
    with left:
        st.markdown("#### Risk History")
        history = detections.sort_values("timestamp").set_index("timestamp")[["final_risk_score"]].rename(columns={"final_risk_score": "Risk Score"})
        st.line_chart(history, color="#398cff", height=285)
    with right:
        st.markdown("#### Recent Deviations")
        deviating = detections[detections["final_risk_score"] >= config.ALERT_MINIMUM_SCORE]
        if deviating.empty:
            st.success("No recent activity crossed the alert threshold.", icon="✅")
        else:
            deviations = _friendly_table(deviating[["timestamp", "activity_type", "final_risk_score", "risk_level"]].head(8), {"timestamp": "Time", "activity_type": "Activity", "final_risk_score": "Risk", "risk_level": "Level"})
            st.dataframe(deviations, hide_index=True, width="stretch", column_config={"Risk": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.1f")})
    st.markdown("#### Activity History")
    activity_history = _friendly_table(
        detections[["timestamp", "activity_type", "scenario", "final_risk_score", "risk_level", "explanation"]].head(50),
        {"timestamp": "Time (UTC)", "activity_type": "Activity", "scenario": "Scenario", "final_risk_score": "Risk Score", "risk_level": "Risk Level", "explanation": "Explanation"},
    )
    st.dataframe(activity_history, hide_index=True, width="stretch", column_config={"Risk Score": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.1f"), "Explanation": st.column_config.TextColumn(width="large")})


def _display_detection(result: object, alert_generated: bool | None = None) -> None:
    data = asdict(result)
    level = data["risk_level"]
    st.subheader("Detection Result")
    st.markdown(f"### {data['final_risk_score']:.2f} / 100 &nbsp; {_risk_badge(level)}", unsafe_allow_html=True)
    st.progress(min(float(data["final_risk_score"]) / 100, 1.0))
    columns = st.columns(4)
    columns[0].metric("Final Risk", f"{data['final_risk_score']:.2f}")
    columns[1].metric("Rule Contribution", f"{data['rule_contribution']:.2f}")
    columns[2].metric("AI Contribution", f"{data['ai_contribution']:.2f}")
    columns[3].metric("Context Contribution", f"{data['contextual_contribution']:.2f}")
    if alert_generated is not None:
        if alert_generated:
            st.error("Alert generated and added to the investigation queue.", icon="🚨")
        else:
            st.success("No alert generated; this result is below the configured alert threshold.", icon="✅")
    if data["model_status"] != "ready":
        _model_status_notice(data["model_status"])
    st.markdown("#### Why this result occurred")
    st.write(data["explanation"])
    rules = _rules_table(data["triggered_rules"])
    if rules.empty:
        st.success("No deterministic threat rule fired.", icon="✅")
    else:
        st.dataframe(rules, hide_index=True, width="stretch")
    st.markdown("#### Recommended administrator response")
    st.info(data["recommended_response"], icon="🛡️")


def render_threat_simulation(service: SentinelService) -> None:
    _page_header("Threat Simulation", "Run guided scenarios through the real persisted detection path and explain every contribution live.")
    _model_status_notice(service.model_status)
    employees = service.employees()
    if not employees:
        st.info("No employees are available for simulation. Initialize or reseed the deterministic demo from the sidebar.", icon="ℹ️")
        return

    setup_left, setup_right = st.columns((1, 1.25))
    with setup_left:
        employee = st.selectbox("Target employee", employees, format_func=lambda item: f"{item.employee_name} · {item.department}")
    with setup_right:
        label = st.selectbox("Simulation scenario", list(SIMULATION_SCENARIOS))
    guide = SCENARIO_GUIDE[label]
    st.markdown(
        f'<div class="scenario-card"><small>{escape(guide["category"])}</small><br>'
        f'<strong>{escape(label)}</strong><p>{escape(guide["description"])}</p>'
        f'<span class="muted"><strong>Expected evidence:</strong> {escape(guide["expected"])}</span></div>',
        unsafe_allow_html=True,
    )
    if st.button("Run Simulation", type="primary", width="stretch", icon="▶️"):
        result = service.simulate(SIMULATION_SCENARIOS[label], employee.employee_id)
        alert_generated = any(alert["event_id"] == result.event_id for alert in service.alert_rows())
        st.session_state["last_simulation_result"] = result
        st.session_state["last_simulation_label"] = label
        st.session_state["last_simulation_alert"] = alert_generated
    result = st.session_state.get("last_simulation_result")
    if result is not None:
        st.caption(f"Latest simulation: {st.session_state.get('last_simulation_label', 'Scenario')} · persisted event {result.event_id}")
        _display_detection(result, st.session_state.get("last_simulation_alert"))

    st.divider()
    st.markdown("#### Demo comparison guide")
    comparison = st.columns(4)
    for column, scenario_name in zip(comparison, ("Normal login", "Unknown-device login", "Combined account compromise", "Legitimate employee travel")):
        scenario = SCENARIO_GUIDE[scenario_name]
        column.markdown(f"**{scenario_name}**")
        column.caption(scenario["category"])
        column.write(scenario["expected"])


def render_alert_investigation(service: SentinelService) -> None:
    _page_header("Alert Investigation", "Review complete evidence, document analyst decisions, and manage each alert through resolution.")
    _model_status_notice(service.model_status)
    flash_message = st.session_state.pop("alert_confirmation", None)
    if flash_message:
        st.success(flash_message, icon="✅")
    alerts = service.alert_rows()
    if not alerts:
        st.success("No alerts currently require investigation. Run a suspicious simulation to create one.", icon="✅")
        return
    filter_columns = st.columns(2)
    status_filter = filter_columns[0].selectbox("Filter by status", ["All statuses"] + list(config.ALERT_STATUSES))
    risk_filter = filter_columns[1].selectbox("Filter by risk", ["All risk levels", "Medium", "High", "Critical"])
    visible_alerts = [alert for alert in alerts if status_filter == "All statuses" or alert["status"] == status_filter]
    visible_alerts = [alert for alert in visible_alerts if risk_filter == "All risk levels" or alert["risk_level"] == risk_filter]
    if not visible_alerts:
        st.info("No alerts match the selected status and risk filters.", icon="🔎")
        return
    selected_alert_id = st.selectbox(
        "Select an alert",
        [alert["alert_id"] for alert in visible_alerts],
        format_func=lambda value: next(f"{_risk_display(item['risk_level'])} · {item['employee_name']} · {item['title']} · {item['status']}" for item in visible_alerts if item["alert_id"] == value),
    )
    alert = service.database.get_alert_row(selected_alert_id)
    if alert is None:
        st.error("The selected alert no longer exists. Refresh the page and choose another alert.", icon="⚠️")
        return
    st.markdown(f"## {escape(alert['title'])} &nbsp; {_risk_badge(alert['risk_level'])}", unsafe_allow_html=True)
    columns = st.columns(4)
    columns[0].metric("Risk Score", f"{alert['risk_score']:.2f} / 100")
    columns[1].metric("Employee", alert["employee_name"])
    columns[2].metric("Status", alert["status"])
    columns[3].metric("Scenario", str(alert["scenario"]).replace("_", " ").title())
    summary_tab, evidence_tab, context_tab = st.tabs(("Alert summary", "Triggered evidence", "Employee + event context"))
    with summary_tab:
        st.markdown("**Why this alert was created**")
        st.write(alert["explanation"])
        st.info(f"Recommended response: {alert['recommended_response']}", icon="🛡️")
    with evidence_tab:
        evidence = _rules_table(alert.get("triggered_rules", []))
        if evidence.empty:
            st.info("This alert was generated from AI anomaly contribution without a deterministic rule hit.")
        else:
            st.dataframe(evidence, hide_index=True, width="stretch")
    with context_tab:
        context = {
            "Employee": alert.get("employee_name"), "Department": alert.get("department"), "Employee ID": alert.get("employee_id"),
            "Event time": alert.get("timestamp"), "Activity": alert.get("activity_type"), "Location": f"{alert.get('city')}, {alert.get('country')}",
            "Device": alert.get("device_id"), "File": alert.get("file_name") or "None", "File sensitivity": alert.get("file_sensitivity"),
            "Model status": alert.get("model_status"), "Anomaly percentile": alert.get("anomaly_percentile"),
        }
        context_rows = [(field, str(value)) for field, value in context.items()]
        st.dataframe(pd.DataFrame(context_rows, columns=["Field", "Value"]), hide_index=True, width="stretch")
        with st.expander("Model feature values"):
            features = alert.get("feature_values", {})
            feature_frame = pd.DataFrame(features.items(), columns=["Feature", "Value"])
            if not feature_frame.empty:
                feature_frame["Feature"] = feature_frame["Feature"].str.replace("_", " ").str.title()
                st.dataframe(feature_frame, hide_index=True, width="stretch")

    st.subheader("Investigation Workflow")
    status_column, action_column = st.columns((2, 1))
    status = status_column.selectbox("Alert status", config.ALERT_STATUSES, index=config.ALERT_STATUSES.index(alert["status"]))
    if action_column.button("Save Status", width="stretch", disabled=status == alert["status"]):
        service.update_alert_status(selected_alert_id, status)
        st.session_state["alert_confirmation"] = f"Alert status updated to {status}."
        st.rerun()
    note = st.text_area("Investigation note", placeholder="Record validation steps, employee confirmation, or analyst rationale…")
    if st.button("Save Note", disabled=not note.strip()):
        service.add_investigation_note(selected_alert_id, note)
        st.session_state["alert_confirmation"] = "Investigation note saved."
        st.rerun()
    notes = service.database.list_investigation_notes(selected_alert_id)
    st.markdown("#### Investigation Notes")
    if notes:
        note_frame = pd.DataFrame(notes).rename(columns={"created_at": "Created", "note": "Analyst Note"})
        st.dataframe(note_frame[["Created", "Analyst Note"]], hide_index=True, width="stretch")
    else:
        st.caption("No investigation notes have been added yet.")


def main() -> None:
    st.set_page_config(page_title="SentinelAI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    _apply_theme()
    try:
        service = get_service()
    except (sqlite3.Error, OSError, RuntimeError):
        _page_header("SentinelAI Unavailable", "The local application could not connect to or initialize its database.")
        st.error("The SentinelAI database is not initialized or cannot be opened. Verify the project data directory, then run the initialization command.", icon="⚠️")
        st.code(".venv/bin/python scripts/initialize_demo.py --reseed", language="bash")
        st.stop()
    with st.sidebar:
        st.title("🛡️ SentinelAI")
        st.caption("Explainable behavioural threat detection for employee activity")
        st.markdown("#### Navigation")
        page = st.radio("Navigate", PAGE_NAMES, label_visibility="collapsed")
        st.divider()
        st.markdown("#### System Status")
        _sidebar_status(service)
        if service.model_status != "ready":
            st.warning("AI model unavailable", icon="⚠️")
        st.divider()
        if st.session_state.pop("reseed_confirmation", False):
            st.success("Demo data reseeded.")
        if st.button("Reseed Demo Data", width="stretch", help="Restore the deterministic employee activity dataset and rerun detection."):
            service.reseed()
            st.session_state.pop("last_simulation_result", None)
            st.session_state.pop("last_simulation_alert", None)
            st.session_state["reseed_confirmation"] = True
            st.rerun()

    renderers = {
        "Dashboard": render_dashboard,
        "Activity Monitor": render_activity_monitor,
        "User Behaviour": render_user_behaviour,
        "Threat Simulation": render_threat_simulation,
        "Alert Investigation": render_alert_investigation,
    }
    renderers[page](service)
