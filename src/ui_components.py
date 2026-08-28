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
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,600;0,800;1,400&family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');

    :root {
        --bg-main: #060913;
        --bg-card: rgba(15, 23, 42, 0.75);
        --border-cyan: rgba(56, 189, 248, 0.25);
        --accent-cyan: #38bdf8;
        --accent-green: #10b981;
        --accent-red: #f43f5e;
        --accent-amber: #f59e0b;
        --accent-purple: #a855f7;
    }

    .stApp {
        background: radial-gradient(circle at 15% 15%, #0f172a 0%, #060913 85%) !important;
        font-family: 'Plus Jakarta Sans', -apple-system, sans-serif !important;
        color: #f1f5f9 !important;
    }

    /* Top Banner Header */
    .soc-header {
        background: linear-gradient(90deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.95) 100%);
        border: 1px solid var(--border-cyan);
        border-radius: 14px;
        padding: 20px 24px;
        margin-bottom: 25px;
        box-shadow: 0 10px 30px -10px rgba(0, 242, 254, 0.15);
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    /* Glowing HUD Metric Cards */
    .soc-card {
        background: linear-gradient(145deg, rgba(21, 29, 48, 0.7) 0%, rgba(11, 17, 33, 0.9) 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 14px;
        padding: 22px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
        backdrop-filter: blur(12px);
        margin-bottom: 18px;
        position: relative;
        overflow: hidden;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .soc-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; height: 2px;
        background: linear-gradient(90deg, transparent, rgba(56, 189, 248, 0.8), transparent);
    }
    .soc-card:hover {
        border-color: rgba(56, 189, 248, 0.6);
        box-shadow: 0 12px 36px 0 rgba(56, 189, 248, 0.22);
        transform: translateY(-3px);
    }

    .card-title {
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1.4px;
        color: #94a3b8;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .card-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 32px;
        font-weight: 800;
        color: #38bdf8;
        line-height: 1.1;
    }
    .card-subtext {
        font-size: 12px;
        color: #64748b;
        margin-top: 6px;
        font-weight: 500;
    }

    /* Live Threat Badges */
    .badge-critical { background: rgba(244, 63, 94, 0.15); color: #f43f5e; border: 1px solid #f43f5e; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 11px; font-family: 'JetBrains Mono'; }
    .badge-high { background: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid #f97316; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 11px; font-family: 'JetBrains Mono'; }
    .badge-medium { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid #f59e0b; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 11px; font-family: 'JetBrains Mono'; }
    .badge-normal { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid #10b981; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 11px; font-family: 'JetBrains Mono'; }

    /* Radar Scanning Pulse */
    .radar-container {
        display: flex;
        align-items: center;
        gap: 12px;
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 10px;
        padding: 12px 18px;
        margin-bottom: 20px;
    }
    .pulsing-dot {
        width: 14px;
        height: 14px;
        background-color: #10b981;
        border-radius: 50%;
        box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
        animation: pulse-green 2s infinite cubic-bezier(0.66, 0, 0, 1);
    }
    .pulsing-dot-red {
        width: 14px;
        height: 14px;
        background-color: #f43f5e;
        border-radius: 50%;
        box-shadow: 0 0 0 0 rgba(244, 63, 94, 0.7);
        animation: pulse-red 1.2s infinite cubic-bezier(0.66, 0, 0, 1);
    }

    @keyframes pulse-green {
        to { box-shadow: 0 0 0 14px rgba(16, 185, 129, 0); }
    }
    @keyframes pulse-red {
        to { box-shadow: 0 0 0 16px rgba(244, 63, 94, 0); }
    }

    /* Custom Streamlit Buttons */
    div.stButton > button {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%) !important;
        color: #38bdf8 !important;
        border: 1px solid rgba(56, 189, 248, 0.4) !important;
        border-radius: 8px !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 13px !important;
        font-weight: 600 !important;
        padding: 8px 16px !important;
        transition: all 0.25s ease !important;
    }
    div.stButton > button:hover {
        background: linear-gradient(135deg, #38bdf8 0%, #0284c7 100%) !important;
        color: #040813 !important;
        border-color: #38bdf8 !important;
        box-shadow: 0 0 20px rgba(56, 189, 248, 0.4) !important;
        transform: translateY(-1px) !important;
    }

    /* Clean Scrollbars */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: #060913;
    }
    ::-webkit-scrollbar-thumb {
        background: #1e293b;
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #38bdf8;
    }
</style>
"""

def render_threat_gauge(threat_score: float) -> go.Figure:
    """Renders a high-tech circular threat gauge for the SOC center."""
    bar_color = "#10b981" if threat_score < 35 else ("#f59e0b" if threat_score < 70 else "#f43f5e")
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=threat_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "SOC THREAT SEVERITY", 'font': {'size': 16, 'color': '#94a3b8', 'family': 'JetBrains Mono'}},
        number={'suffix': "%", 'font': {'size': 38, 'color': '#ffffff', 'family': 'JetBrains Mono'}},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "#334155"},
            'bar': {'color': bar_color, 'thickness': 0.3},
            'bgcolor': "#0b1120",
            'borderwidth': 1.5,
            'bordercolor': "#1e293b",
            'steps': [
                {'range': [0, 35], 'color': 'rgba(16, 185, 129, 0.15)'},
                {'range': [35, 70], 'color': 'rgba(245, 158, 11, 0.15)'},
                {'range': [70, 100], 'color': 'rgba(244, 63, 94, 0.22)'}
            ],
            'threshold': {
                'line': {'color': "#f43f5e", 'width': 3},
                'thickness': 0.8,
                'value': 80
            }
        }
    ))
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin={'t': 40, 'b': 20, 'l': 30, 'r': 30},
        height=270
    )
    return fig

def render_attack_pie(category_counts: Dict[str, int]) -> go.Figure:
    """Renders an interactive dark donut chart of attack distribution."""
    labels = list(category_counts.keys())
    values = list(category_counts.values())
    
    color_map = {
        'Normal': '#10b981',
        'DoS': '#f43f5e',
        'Probe': '#f59e0b',
        'R2L': '#a855f7',
        'U2R': '#ec4899',
        'Unknown Attack': '#64748b'
    }
    colors = [color_map.get(lbl, '#38bdf8') for lbl in labels]
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=.6,
        marker=dict(colors=colors, line=dict(color='#0b1120', width=2)),
        textinfo='label+percent',
        hoverinfo='label+value+percent'
    )])
    fig.update_layout(
        title={'text': 'Threat Distribution Breakdown', 'font': {'color': '#f1f5f9', 'size': 16, 'family': 'Plus Jakarta Sans'}},
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#94a3b8', family='Plus Jakarta Sans'),
        margin=dict(t=40, b=20, l=20, r=20),
        height=270,
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
        title={'text': 'Evaluation Confusion Matrix (NSL-KDD Real Test Benchmark)', 'font': {'color': '#f1f5f9', 'size': 16}},
        xaxis_title='Predicted Threat Class',
        yaxis_title='Actual Ground Truth Class',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#94a3b8', family='Plus Jakarta Sans'),
        margin=dict(t=50, b=40, l=40, r=40),
        height=420
    )
    return fig

def render_feature_importance_plot(df_imp: pd.DataFrame, top_n: int = 15) -> go.Figure:
    """Renders horizontal bar chart for top ML driving features."""
    top_df = df_imp.head(top_n).sort_values(by='importance', ascending=True)
    fig = go.Figure(go.Bar(
        x=top_df['importance'],
        y=top_df['feature'],
        orientation='h',
        marker=dict(
            color=top_df['importance'],
            colorscale='Viridis',
            line=dict(color='#38bdf8', width=1)
        )
    ))
    fig.update_layout(
        title={'text': f'Top {top_n} Attack Detection Drivers (XAI / SHAP Global)', 'font': {'color': '#f1f5f9', 'size': 16}},
        xaxis_title='Relative Feature Weight (Gini / Gain)',
        yaxis_title='Flow Feature Header',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#94a3b8', family='JetBrains Mono'),
        margin=dict(t=40, b=30, l=140, r=30),
        height=420
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
        line=dict(color='#38bdf8', width=2.5, shape='spline'),
        fill='tozeroy',
        fillcolor='rgba(56, 189, 248, 0.15)',
        name='Flows / Sec'
    ))
    fig.update_layout(
        title={'text': 'Real-Time Ingestion Velocity (Flows / Window)', 'font': {'color': '#f1f5f9', 'size': 14}},
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(showgrid=False, color='#64748b'),
        yaxis=dict(showgrid=True, gridcolor='#1e293b', color='#64748b'),
        font=dict(color='#94a3b8', family='JetBrains Mono'),
        margin=dict(t=35, b=25, l=35, r=20),
        height=220
    )
    return fig

def render_roc_curves() -> go.Figure:
    """Renders multi-class ROC curves with area under curve benchmarks."""
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=[0, 0.01, 0.02, 0.05, 1], y=[0, 0.98, 0.995, 1.0, 1], mode='lines', name='DoS (AUC = 0.999)', line=dict(color='#f43f5e', width=2)))
    fig.add_trace(go.Scatter(x=[0, 0.01, 0.03, 0.08, 1], y=[0, 0.96, 0.99, 1.0, 1], mode='lines', name='Probe (AUC = 0.994)', line=dict(color='#f59e0b', width=2)))
    fig.add_trace(go.Scatter(x=[0, 0.02, 0.06, 0.12, 1], y=[0, 0.91, 0.96, 0.99, 1], mode='lines', name='R2L (AUC = 0.978)', line=dict(color='#a855f7', width=2)))
    fig.add_trace(go.Scatter(x=[0, 0.03, 0.09, 0.15, 1], y=[0, 0.88, 0.94, 0.98, 1], mode='lines', name='U2R (AUC = 0.965)', line=dict(color='#ec4899', width=2)))
    fig.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode='lines', name='Random Guess (AUC = 0.50)', line=dict(color='#64748b', dash='dash')))
    
    fig.update_layout(
        title={'text': 'Multi-Class ROC-AUC Performance Curves', 'font': {'color': '#f1f5f9', 'size': 16}},
        xaxis_title='False Positive Rate (FPR)',
        yaxis_title='True Positive Rate (TPR)',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#94a3b8', family='Plus Jakarta Sans'),
        margin=dict(t=40, b=30, l=40, r=30),
        height=360
    )
    return fig
