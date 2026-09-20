"""
dashboard.py — Streamlit dashboard for InsightGraph

Premium dark-themed threat intelligence dashboard.
Calls the FastAPI backend and displays final report output only (no logs).

Run:
    streamlit run dashboard.py
"""

import streamlit as st
import requests
import plotly.graph_objects as go
import plotly.express as px

# ══════════════════════════════════════════════════════════════════════════════
# Page Config
# ══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="InsightGraph — Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_BASE = "http://localhost:8000"

# ══════════════════════════════════════════════════════════════════════════════
# Custom CSS — Premium Dark Theme
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<style>
    /* ── Base theme ── */
    .stApp {
        background: linear-gradient(135deg, #0a0a1a 0%, #0d1117 50%, #0a0a1a 100%);
    }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1117 0%, #161b22 100%);
        border-right: 1px solid rgba(48, 54, 61, 0.6);
    }

    /* ── Metric cards ── */
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95));
        border: 1px solid rgba(48, 54, 61, 0.6);
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    div[data-testid="stMetric"]:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
    }
    div[data-testid="stMetric"] label {
        color: #8b949e !important;
        font-size: 0.85rem !important;
        font-weight: 500 !important;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #e6edf3 !important;
        font-size: 2rem !important;
        font-weight: 700 !important;
    }

    /* ── Section headers ── */
    .section-header {
        background: linear-gradient(90deg, rgba(56, 139, 253, 0.12), transparent);
        border-left: 3px solid #388bfd;
        padding: 12px 18px;
        margin: 28px 0 16px 0;
        border-radius: 0 8px 8px 0;
        font-size: 1.15rem;
        font-weight: 600;
        color: #e6edf3;
        letter-spacing: 0.3px;
    }

    /* ── Cards ── */
    .insight-card {
        background: linear-gradient(135deg, rgba(22, 27, 34, 0.85), rgba(13, 17, 23, 0.9));
        border: 1px solid rgba(48, 54, 61, 0.5);
        border-radius: 12px;
        padding: 20px 24px;
        margin: 8px 0;
        box-shadow: 0 2px 12px rgba(0, 0, 0, 0.2);
    }

    /* ── Summary card ── */
    .summary-card {
        background: linear-gradient(135deg, rgba(56, 139, 253, 0.08), rgba(22, 27, 34, 0.9));
        border: 1px solid rgba(56, 139, 253, 0.25);
        border-radius: 14px;
        padding: 24px 28px;
        margin: 12px 0 20px 0;
        font-size: 1.05rem;
        line-height: 1.7;
        color: #c9d1d9;
        box-shadow: 0 4px 24px rgba(56, 139, 253, 0.08);
    }

    /* ── Severity badges ── */
    .badge-critical {
        background: rgba(248, 81, 73, 0.15);
        color: #f85149;
        border: 1px solid rgba(248, 81, 73, 0.3);
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.5px;
    }
    .badge-high {
        background: rgba(210, 153, 34, 0.15);
        color: #d29922;
        border: 1px solid rgba(210, 153, 34, 0.3);
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .badge-medium {
        background: rgba(56, 139, 253, 0.15);
        color: #388bfd;
        border: 1px solid rgba(56, 139, 253, 0.3);
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .badge-low, .badge-clean {
        background: rgba(63, 185, 80, 0.15);
        color: #3fb950;
        border: 1px solid rgba(63, 185, 80, 0.3);
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    /* ── Recommendation cards ── */
    .rec-card {
        background: linear-gradient(135deg, rgba(22, 27, 34, 0.8), rgba(13, 17, 23, 0.85));
        border: 1px solid rgba(48, 54, 61, 0.5);
        border-left: 3px solid #388bfd;
        border-radius: 0 10px 10px 0;
        padding: 16px 20px;
        margin: 8px 0;
        color: #c9d1d9;
        font-size: 0.95rem;
        line-height: 1.6;
    }

    /* ── IOC tag ── */
    .ioc-tag {
        display: inline-block;
        background: rgba(248, 81, 73, 0.1);
        border: 1px solid rgba(248, 81, 73, 0.25);
        color: #f85149;
        padding: 5px 14px;
        border-radius: 6px;
        margin: 4px 6px 4px 0;
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 0.85rem;
    }

    /* ── Threat row ── */
    .threat-row {
        background: linear-gradient(135deg, rgba(22, 27, 34, 0.7), rgba(13, 17, 23, 0.8));
        border: 1px solid rgba(48, 54, 61, 0.4);
        border-radius: 10px;
        padding: 16px 20px;
        margin: 8px 0;
    }
    .threat-row:hover {
        border-color: rgba(56, 139, 253, 0.4);
    }

    /* ── Actor row ── */
    .actor-row {
        background: rgba(22, 27, 34, 0.6);
        border: 1px solid rgba(48, 54, 61, 0.3);
        border-radius: 8px;
        padding: 12px 16px;
        margin: 6px 0;
    }

    /* ── Hide Streamlit footer + hamburger ── */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}

    /* ── Dataframe styling ── */
    .stDataFrame {
        border-radius: 10px;
        overflow: hidden;
    }

    /* ── Plotly chart background fix ── */
    .js-plotly-plot .plotly .main-svg {
        border-radius: 12px;
    }
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# Helper: severity badge
# ══════════════════════════════════════════════════════════════════════════════

def severity_badge(severity: str) -> str:
    sev = severity.upper()
    css_class = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low",
        "CLEAN": "badge-clean",
    }.get(sev, "badge-low")
    return f'<span class="{css_class}">{sev}</span>'


# ══════════════════════════════════════════════════════════════════════════════
# Plotly theme defaults
# ══════════════════════════════════════════════════════════════════════════════

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#c9d1d9", family="Inter, sans-serif"),
    margin=dict(l=40, r=40, t=40, b=40),
    legend=dict(
        bgcolor="rgba(22,27,34,0.8)",
        bordercolor="rgba(48,54,61,0.5)",
        borderwidth=1,
        font=dict(size=12),
    ),
)

SEVERITY_COLORS_MAP = {
    "CRITICAL": "#f85149",
    "HIGH": "#d29922",
    "MEDIUM": "#388bfd",
    "LOW": "#3fb950",
    "CLEAN": "#3fb950",
}

ROLE_COLORS = {
    "Origin": "#388bfd",
    "Amplifier": "#f85149",
    "Bridge": "#d29922",
    "Echo": "#a371f7",
    "Endpoint": "#8b949e",
}


# ══════════════════════════════════════════════════════════════════════════════
# Sidebar
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## 🛡️ InsightGraph")
    st.markdown(
        '<p style="color: #8b949e; font-size: 0.9rem; margin-top: -10px;">'
        'Social Threat Intelligence Platform</p>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    subreddit = st.text_input(
        "Target Subreddit",
        placeholder="e.g. buildapc",
        help="Enter the subreddit name without the r/ prefix",
    )

    analyze_btn = st.button("🔍  Run Analysis", type="primary", use_container_width=True)

    st.markdown("---")
    st.markdown(
        '<p style="color: #484f58; font-size: 0.75rem; text-align: center;">'
        'Powered by LangGraph • FastAPI • Streamlit</p>',
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Main Content
# ══════════════════════════════════════════════════════════════════════════════

# Title
st.markdown(
    '<h1 style="color: #e6edf3; font-weight: 700; margin-bottom: 0;">'
    '🛡️ InsightGraph Dashboard</h1>',
    unsafe_allow_html=True,
)
st.markdown(
    '<p style="color: #8b949e; font-size: 1.05rem; margin-top: 4px;">'
    'Real-time threat intelligence analysis for Reddit communities</p>',
    unsafe_allow_html=True,
)

# ── Run analysis ──
if analyze_btn and subreddit:
    with st.spinner(f"🔄 Analyzing r/{subreddit} — this may take a few minutes..."):
        try:
            resp = requests.post(
                f"{API_BASE}/api/analyze",
                json={"subreddit": subreddit},
                timeout=600,
            )
            if resp.status_code == 200:
                st.session_state["result"] = resp.json()
                st.session_state["subreddit"] = subreddit
            else:
                detail = resp.json().get("detail", resp.text)
                st.error(f"❌ Analysis failed: {detail}")
        except requests.ConnectionError:
            st.error(
                "❌ Cannot connect to the API server. "
                "Make sure to run: `uvicorn api:app --reload --port 8000`"
            )
        except requests.Timeout:
            st.error("❌ Analysis timed out. Try a smaller subreddit.")
        except Exception as e:
            st.error(f"❌ Unexpected error: {e}")

elif analyze_btn and not subreddit:
    st.warning("⚠️ Please enter a subreddit name.")


# ══════════════════════════════════════════════════════════════════════════════
# Display Results
# ══════════════════════════════════════════════════════════════════════════════

if "result" in st.session_state:
    data = st.session_state["result"]
    report = data.get("report", {})
    threat_summary = data.get("threat_summary", {})
    propagation = data.get("propagation_summary", {})
    threat_results = data.get("threat_results", [])
    sub_name = st.session_state.get("subreddit", "?")

    st.markdown(f"---")

    # ────────────────────────────────────────────────────────────────────────
    # Executive Summary
    # ────────────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">📝 Executive Summary</div>', unsafe_allow_html=True)
    summary_text = report.get("executive_summary", "No summary available.")
    st.markdown(f'<div class="summary-card">{summary_text}</div>', unsafe_allow_html=True)

    # ────────────────────────────────────────────────────────────────────────
    # Threat Overview — Metric Cards
    # ────────────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🛡️ Threat Overview</div>', unsafe_allow_html=True)

    by_sev = threat_summary.get("by_severity", {})
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Analyzed", threat_summary.get("total_analyzed", 0))
    col2.metric("Threats Found", threat_summary.get("total_threats", 0))
    col3.metric("🔴 Critical", by_sev.get("CRITICAL", 0))
    col4.metric("🟡 High", by_sev.get("HIGH", 0))
    col5.metric("🔵 Medium", by_sev.get("MEDIUM", 0))

    # ────────────────────────────────────────────────────────────────────────
    # Charts Row — Severity Breakdown + Threat Types
    # ────────────────────────────────────────────────────────────────────────
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown('<div class="section-header">📊 Severity Breakdown</div>', unsafe_allow_html=True)
        sev_data = threat_summary.get("by_severity", {})
        if sev_data:
            severities = list(sev_data.keys())
            counts = list(sev_data.values())
            colors = [SEVERITY_COLORS_MAP.get(s, "#8b949e") for s in severities]

            fig = go.Figure(data=[
                go.Bar(
                    x=severities,
                    y=counts,
                    marker=dict(
                        color=colors,
                        line=dict(width=0),
                        cornerradius=6,
                    ),
                    text=counts,
                    textposition="outside",
                    textfont=dict(color="#e6edf3", size=14, family="Inter"),
                )
            ])
            fig.update_layout(
                **PLOTLY_LAYOUT,
                xaxis=dict(showgrid=False, color="#8b949e"),
                yaxis=dict(showgrid=True, gridcolor="rgba(48,54,61,0.3)", color="#8b949e"),
                height=350,
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No severity data available.")

    with chart_col2:
        st.markdown('<div class="section-header">🎯 Threat Types</div>', unsafe_allow_html=True)
        type_data = threat_summary.get("by_type", {})
        if type_data:
            labels = list(type_data.keys())
            values = list(type_data.values())

            fig = go.Figure(data=[
                go.Pie(
                    labels=labels,
                    values=values,
                    hole=0.45,
                    marker=dict(
                        colors=px.colors.qualitative.Set2[:len(labels)],
                        line=dict(color="rgba(13,17,23,0.9)", width=2),
                    ),
                    textinfo="label+percent",
                    textfont=dict(size=12, color="#e6edf3"),
                    hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
                )
            ])
            fig.update_layout(
                **PLOTLY_LAYOUT,
                height=350,
                showlegend=True,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat type data available.")

    # ────────────────────────────────────────────────────────────────────────
    # Combined Risk by Subreddit
    # ────────────────────────────────────────────────────────────────────────
    combined_risk = report.get("combined_risk_by_subreddit", {})
    if combined_risk:
        st.markdown('<div class="section-header">⚠️ Combined Risk by Subreddit</div>', unsafe_allow_html=True)

        risk_rows = []
        for sub, d in sorted(combined_risk.items(), key=lambda x: x[1]["risk_score"], reverse=True):
            risk_rows.append({
                "Subreddit": sub,
                "Risk Score": d["risk_score"],
                "Risk Level": d["risk_label"],
                "Avg Threat Score": d["avg_threat_score"],
                "Propagation Score": d["propagation_score"],
                "Posts": d["post_count"],
            })

        if risk_rows:
            import pandas as pd
            df = pd.DataFrame(risk_rows)

            def color_risk(val):
                colors = {
                    "CRITICAL": "background-color: rgba(248,81,73,0.15); color: #f85149; font-weight: 600",
                    "HIGH": "background-color: rgba(210,153,34,0.15); color: #d29922; font-weight: 600",
                    "MEDIUM": "background-color: rgba(56,139,253,0.15); color: #388bfd; font-weight: 600",
                    "LOW": "background-color: rgba(63,185,80,0.15); color: #3fb950; font-weight: 600",
                }
                return colors.get(val, "")

            styled = df.style.applymap(color_risk, subset=["Risk Level"])
            st.dataframe(styled, use_container_width=True, hide_index=True)

    # ────────────────────────────────────────────────────────────────────────
    # Propagation Overview
    # ────────────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🔗 Propagation Overview</div>', unsafe_allow_html=True)

    prop_col1, prop_col2, prop_col3, prop_col4 = st.columns(4)
    prop_col1.metric("Total Users", propagation.get("total_users", 0))
    prop_col2.metric("Total Edges", propagation.get("total_edges", 0))

    cascade = propagation.get("cascade_depth", {})
    prop_col3.metric("Max Cascade Depth", cascade.get("max", 0))

    velocity = propagation.get("temporal_velocity", {})
    prop_col4.metric("Peak Posts/Hour", velocity.get("posts_per_hour", 0))

    # Role distribution chart
    role_dist = propagation.get("role_distribution", {})
    if role_dist:
        role_col1, role_col2 = st.columns([2, 1])

        with role_col1:
            roles = list(role_dist.keys())
            role_counts = list(role_dist.values())
            role_colors = [ROLE_COLORS.get(r, "#8b949e") for r in roles]

            fig = go.Figure(data=[
                go.Bar(
                    x=roles,
                    y=role_counts,
                    marker=dict(
                        color=role_colors,
                        line=dict(width=0),
                        cornerradius=6,
                    ),
                    text=role_counts,
                    textposition="outside",
                    textfont=dict(color="#e6edf3", size=13),
                )
            ])
            fig.update_layout(
                **PLOTLY_LAYOUT,
                xaxis=dict(showgrid=False, color="#8b949e"),
                yaxis=dict(showgrid=True, gridcolor="rgba(48,54,61,0.3)", color="#8b949e"),
                height=300,
                showlegend=False,
                title=dict(text="Role Distribution", font=dict(size=14, color="#8b949e")),
            )
            st.plotly_chart(fig, use_container_width=True)

        with role_col2:
            st.markdown("")
            st.markdown("")
            for role in ["Origin", "Amplifier", "Bridge", "Echo", "Endpoint"]:
                count = role_dist.get(role, 0)
                color = ROLE_COLORS.get(role, "#8b949e")
                st.markdown(
                    f'<div class="actor-row">'
                    f'<span style="color: {color}; font-weight: 600;">{role}</span>'
                    f'<span style="float: right; color: #e6edf3; font-weight: 700;">{count}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    # ────────────────────────────────────────────────────────────────────────
    # Key Actors
    # ────────────────────────────────────────────────────────────────────────
    key_actors = report.get("key_actors", [])
    if key_actors:
        st.markdown('<div class="section-header">👤 Key Actors</div>', unsafe_allow_html=True)

        for actor in key_actors[:10]:
            role = actor.get("role", "?")
            color = ROLE_COLORS.get(role, "#8b949e")
            score = actor.get("score", 0)
            st.markdown(
                f'<div class="actor-row">'
                f'<strong style="color: #e6edf3;">{actor.get("username", "?")}</strong>'
                f'&nbsp;&nbsp;'
                f'<span style="color: {color}; font-weight: 600; font-size: 0.85rem;">{role}</span>'
                f'<span style="float: right;">'
                f'<span style="color: #8b949e; font-size: 0.85rem;">Score: </span>'
                f'<span style="color: #e6edf3; font-weight: 700;">{score:.1f}</span>'
                f'</span>'
                f'<br/>'
                f'<span style="color: #484f58; font-size: 0.8rem;">{actor.get("details", "")}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # ────────────────────────────────────────────────────────────────────────
    # Top 5 Threats
    # ────────────────────────────────────────────────────────────────────────
    top_threats = report.get("top_threats", [])
    if top_threats:
        st.markdown('<div class="section-header">🚨 Top Threats</div>', unsafe_allow_html=True)

        for i, t in enumerate(top_threats[:5], 1):
            sev = t.get("severity", "CLEAN")
            badge = severity_badge(sev)
            st.markdown(
                f'<div class="threat-row">'
                f'<div style="display: flex; justify-content: space-between; align-items: center;">'
                f'<div>'
                f'<span style="color: #8b949e; font-size: 0.85rem;">#{i}</span>&nbsp;&nbsp;'
                f'<strong style="color: #e6edf3;">{t.get("post_id", "?")}</strong>'
                f'&nbsp;&nbsp;'
                f'<span style="color: #8b949e;">r/{t.get("subreddit", "?")}</span>'
                f'</div>'
                f'<div>'
                f'{badge}'
                f'&nbsp;&nbsp;'
                f'<span style="color: #e6edf3; font-weight: 700;">{t.get("threat_score", 0):.1f}</span>'
                f'</div>'
                f'</div>'
                f'<div style="margin-top: 8px; color: #8b949e; font-size: 0.85rem;">'
                f'<span style="color: #c9d1d9; font-weight: 500;">{t.get("threat_type", "?")}</span>'
                f'&nbsp;•&nbsp;Confidence: {t.get("confidence", 0):.3f}'
                f'</div>'
                f'<div style="margin-top: 6px; color: #6e7681; font-size: 0.85rem; font-style: italic;">'
                f'📝 {t.get("text_preview", "")[:100]}'
                f'</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # ────────────────────────────────────────────────────────────────────────
    # IOC List
    # ────────────────────────────────────────────────────────────────────────
    iocs = report.get("ioc_list", [])
    if iocs:
        st.markdown(
            f'<div class="section-header">🔍 IOC List ({len(iocs)} domains)</div>',
            unsafe_allow_html=True,
        )
        ioc_html = "".join(f'<span class="ioc-tag">{ioc}</span>' for ioc in iocs[:30])
        st.markdown(
            f'<div class="insight-card">{ioc_html}</div>',
            unsafe_allow_html=True,
        )

    # ────────────────────────────────────────────────────────────────────────
    # Recommendations
    # ────────────────────────────────────────────────────────────────────────
    recs = report.get("recommendations", [])
    if recs:
        st.markdown('<div class="section-header">💡 Recommendations</div>', unsafe_allow_html=True)

        for i, rec in enumerate(recs, 1):
            st.markdown(
                f'<div class="rec-card">'
                f'<span style="color: #388bfd; font-weight: 700; font-size: 1.1rem;">{i}.</span>'
                f'&nbsp;&nbsp;{rec}'
                f'</div>',
                unsafe_allow_html=True,
            )

    # ────────────────────────────────────────────────────────────────────────
    # Footer
    # ────────────────────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown(
        f'<div style="text-align: center; color: #484f58; font-size: 0.8rem; padding: 10px 0;">'
        f'Report ID: {report.get("report_id", "N/A")} &nbsp;•&nbsp; '
        f'Generated: {report.get("generated_at", "N/A")} &nbsp;•&nbsp; '
        f'r/{sub_name}'
        f'</div>',
        unsafe_allow_html=True,
    )

else:
    # ── Landing state ──
    st.markdown("")
    st.markdown("")

    lc1, lc2, lc3 = st.columns(3)
    with lc1:
        st.markdown(
            '<div class="insight-card" style="text-align: center;">'
            '<div style="font-size: 2.5rem; margin-bottom: 12px;">🔍</div>'
            '<div style="color: #e6edf3; font-weight: 600; font-size: 1rem;">Threat Analysis</div>'
            '<div style="color: #8b949e; font-size: 0.85rem; margin-top: 6px;">'
            'ML-powered classification of social engineering threats</div>'
            '</div>',
            unsafe_allow_html=True,
        )
    with lc2:
        st.markdown(
            '<div class="insight-card" style="text-align: center;">'
            '<div style="font-size: 2.5rem; margin-bottom: 12px;">🔗</div>'
            '<div style="color: #e6edf3; font-weight: 600; font-size: 1rem;">Propagation Mapping</div>'
            '<div style="color: #8b949e; font-size: 0.85rem; margin-top: 6px;">'
            'Graph-based detection of amplifiers, bridges & coordinated actors</div>'
            '</div>',
            unsafe_allow_html=True,
        )
    with lc3:
        st.markdown(
            '<div class="insight-card" style="text-align: center;">'
            '<div style="font-size: 2.5rem; margin-bottom: 12px;">📋</div>'
            '<div style="color: #e6edf3; font-weight: 600; font-size: 1rem;">Intelligence Reports</div>'
            '<div style="color: #8b949e; font-size: 0.85rem; margin-top: 6px;">'
            'LLM-generated executive summaries & actionable recommendations</div>'
            '</div>',
            unsafe_allow_html=True,
        )

    st.markdown("")
    st.markdown(
        '<div style="text-align: center; color: #6e7681; font-size: 0.95rem; margin-top: 30px;">'
        '👈 Enter a subreddit name and click <strong>Run Analysis</strong> to begin'
        '</div>',
        unsafe_allow_html=True,
    )
