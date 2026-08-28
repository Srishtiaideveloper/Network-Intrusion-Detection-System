"""
Cyberpunk / Enterprise SOC Design System and UI Component Library.
Provides custom dark glassmorphic styling, real-time threat radars, Plotly telemetry gauges,
and MITRE ATT&CK interactive visual matrices for the Streamlit Command Center.
"""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional

CYBER_THEME_CSS = """
<style>
    /* Global Cyber Dark Theme */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@400;500;600;700&display=swap');

    .stApp {
        background: radial-gradient(circle at 10% 20%, #0b0f19 0%, #060911 90%);
        font-family: 'Inter', sans-serif;
        color: #e2e8f0;
    }

    /* Glowing Metric HUD Cards */
    .soc-card {
        background: linear-gradient(135deg, rgba(21, 29, 48, 0.7) 0%, rgba(15, 23, 42, 0.85) 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        backdrop-filter: blur(8px);
        margin-bottom: 15px;
        transition: all 0.3s ease;
    }
    .soc-card:hover {
        border-color: rgba(56, 189, 248, 0.6);
        box-shadow: 0 8px 32px 0 rgba(56, 189, 248, 0.2);
        transform: translateY(-2px);
    }

    .card-title {
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        color: #94a3b8;
        margin-bottom: 8px;
    }
    .card-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 28px;
        font-weight: 800;
        color: #38bdf8;
    }
    .card-subtext {
        font-size: 12px;
        color: #64748b;
        margin-top: 5px;
    }

    /* Threat Status Badges */
    .badge-critical { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid #ef4444; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .badge-high { background: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid #f97316; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .badge-medium { background: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid #eab308; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .badge-normal { background: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid #22c55e; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }

    /* Pulsing Alert Radar Animation */
    .radar-container {
        display: flex;
        align-items: center;
        gap: 12px;
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 10px 16px;
        margin-bottom: 20px;
    }
    .pulsing-dot {
        width: 12px;
        height: 12px;
        background-color: #22c55e;
        border-radius: 50%;
        box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7);
        animation: pulse-green 2s infinite cubic-bezier(0.66, 0, 0, 1);
    }
    .pulsing-dot-red {
        width: 12px;
        height: 12px;
        background-color: #ef4444;
        border-radius: 50%;
        box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7);
        animation: pulse-red 1.2s infinite cubic-bezier(0.66, 0, 0, 1);
    }

    @keyframes pulse-green {
        to { box-shadow: 0 0 0 12px rgba(34, 197, 94, 0); }
    }
    @keyframes pulse-red {
        to { box-shadow: 0 0 0 14px rgba(239, 68, 68, 0); }
    }
</style>
"""

def render_threat_gauge(threat_score: float) -> go.Figure:
    """Renders a high-tech circular threat gauge for the SOC center."""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=threat_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "SOC THREAT LEVEL", 'font': {'size': 18, 'color': '#38bdf8', 'family': 'JetBrains Mono'}},
        number={'suffix': "%", 'font': {'size': 36, 'color': '#ffffff', 'family': 'JetBrains Mono'}},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "#334155"},
            'bar': {'color': "#38bdf8" if threat_score < 40 else ("#f59e0b" if threat_score < 75 else "#ef4444")},
            'bgcolor': "#0f172a",
            'borderwidth': 2,
            'bordercolor': "#1e293b",
            'steps': [
                {'range': [0, 35], 'color': 'rgba(34, 197, 94, 0.2)'},
                {'range': [35, 70], 'color': 'rgba(234, 179, 8, 0.2)'},
                {'range': [70, 100], 'color': 'rgba(239, 68, 68, 0.25)'}
            ],
            'threshold': {
                'line': {'color': "#ff0055", 'width': 3},
                'thickness': 0.8,
                'value': 85
            }
        }
    ))
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin={'t': 40, 'b': 20, 'l': 30, 'r': 30},
        height=260
    )
    return fig

def render_attack_pie(category_counts: Dict[str, int]) -> go.Figure:
    """Renders an interactive dark donut chart of attack distribution."""
    labels = list(category_counts.keys())
    values = list(category_counts.values())
    
    color_map = {
        'Normal': '#22c55e',
        'DoS': '#ef4444',
        'Probe': '#f59e0b',
        'R2L': '#a855f7',
        'U2R': '#ec4899',
        'Unknown Attack': '#64748b'
    }
    colors = [color_map.get(lbl, '#38bdf8') for lbl in labels]
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=.55,
        marker=dict(colors=colors, line=dict(color='#0f172a', width=2)),
        textinfo='label+percent',
        hoverinfo='label+value+percent'
    )])
    fig.update_layout(
        title={'text': 'Traffic Category Breakdown', 'font': {'color': '#e2e8f0', 'size': 16}},
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#94a3b8', family='Inter'),
        margin=dict(t=40, b=20, l=20, r=20),
        height=280,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
    )
    return fig

def render_confusion_matrix(cm: List[List[int]], class_names: List[str]) -> go.Figure:
    """Renders an annotated cyber heatmap confusion matrix."""
    fig = px.imshow(
        cm,
        x=class_names,
        y=class_names,
        color_continuous_scale='Blues',
        text_auto=True,
        aspect="auto"
    )
    fig.update_layout(
        title={'text': 'Model Confusion Matrix (Authentic Real Test Set)', 'font': {'color': '#e2e8f0', 'size': 16}},
        xaxis_title='Predicted Category',
        yaxis_title='True Category',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#94a3b8', family='Inter'),
        margin=dict(t=50, b=40, l=40, r=40),
        height=400
    )
    return fig

def render_feature_importance_plot(df_imp: pd.DataFrame, top_n: int = 12) -> go.Figure:
    """Renders horizontal bar chart for top ML driving features."""
    top_df = df_imp.head(top_n).sort_values(by='importance', ascending=True)
    fig = go.Figure(go.Bar(
        x=top_df['importance'],
        y=top_df['feature'],
        orientation='h',
        marker=dict(
            color=top_df['importance'],
            colorscale='Teal',
            line=dict(color='#38bdf8', width=1)
        )
    ))
    fig.update_layout(
        title={'text': f'Top {top_n} Attack Detection Drivers (XAI / SHAP)', 'font': {'color': '#e2e8f0', 'size': 16}},
        xaxis_title='Relative Importance Weight',
        yaxis_title='Flow Feature',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#94a3b8', family='Inter'),
        margin=dict(t=40, b=30, l=120, r=30),
        height=380
    )
    return fig

def render_packet_velocity_chart(velocity_history: List[Dict[str, Any]]) -> go.Figure:
    """Renders real-time telemetry sparkline of packet flow velocity."""
    if not velocity_history:
        return go.Figure()
    
    df = pd.DataFrame(velocity_history)
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['packet_rate'],
        mode='lines+markers',
        line=dict(color='#38bdf8', width=2, shape='spline'),
        fill='tozeroy',
        fillcolor='rgba(56, 189, 248, 0.15)',
        name='Flows / Sec'
    ))
    fig.update_layout(
        title={'text': 'Real-Time Flow Telemetry Velocity', 'font': {'color': '#e2e8f0', 'size': 14}},
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(showgrid=False, color='#64748b'),
        yaxis=dict(showgrid=True, gridcolor='#1e293b', color='#64748b'),
        font=dict(color='#94a3b8', family='JetBrains Mono'),
        margin=dict(t=35, b=25, l=35, r=20),
        height=220
    )
    return fig
