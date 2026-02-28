import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import os

st.set_page_config(
    page_title="Network Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stApp {
        background-color: #FFFFFF;
        color: #000000;
    }
    div[data-testid="stMetric"] {
        background-color: #F8F9FA;
        border: 1px solid #DEE2E6;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    div[data-testid="stMetricLabel"] {
        color: #6C757D;
        font-size: 14px;
    }
    div[data-testid="stMetricValue"] {
        color: #212529;
        font-weight: bold;
    }
    h1, h2, h3 {
        color: #212529;
        font-family: 'Arial', sans-serif;
    }
    div[data-testid="stDataFrame"] {
        border: 1px solid #DEE2E6;
    }
</style>
""", unsafe_allow_html=True)

LOG_FILE = "log_data.csv"

def load_data():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame()
    try:
        df = pd.read_csv(LOG_FILE)
        return df
    except:
        return pd.DataFrame()

with st.sidebar:
    st.title("SECURITY CENTER")
    st.markdown("---")
    
    if st.button("REFRESH DATA", use_container_width=True):
        st.rerun()
    
    st.write("")
    
    if st.button("RESET DASHBOARD", type="primary", use_container_width=True):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                f.write("timestamp,source_ip,prediction,label,prob_attack\n")
        st.rerun()
        
    st.markdown("---")
    st.success("System Status: ONLINE")

st.title("REAL-TIME NETWORK TRAFFIC ANALYSIS")

df = load_data()

if df.empty:
    st.info("Waiting for data stream...")
    time.sleep(1)
    st.rerun()

else:
    total_req = len(df)
    attacks = df[df['label'] != 'BENIGN']
    attack_count = len(attacks)
    benign_count = len(df[df['label'] == 'BENIGN'])
    
    attack_rate = (attack_count / total_req * 100) if total_req > 0 else 0
    
    threat_level = "LOW"
    status_color = "#28a745"
    if attack_count > 10: 
        threat_level = "MODERATE"
        status_color = "#ffc107"
    if attack_count > 50: 
        threat_level = "CRITICAL"
        status_color = "#dc3545"

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    
    with kpi1:
        st.metric("Total Packets", f"{total_req}")
    with kpi2:
        st.metric("Attack Detected", f"{attack_count}", delta=f"{attack_rate:.1f}%", delta_color="inverse")
    with kpi3:
        st.metric("Safe Traffic", f"{benign_count}")
    with kpi4:
        st.markdown(f"""
        <div style="background-color:{status_color}; padding:10px; border-radius:5px; text-align:center; color:white; font-weight:bold;">
            THREAT LEVEL: {threat_level}
        </div>
        """, unsafe_allow_html=True)

    col_left, col_right = st.columns([2, 1])

    color_map = {
        'BENIGN': '#28a745',
        'FTP-Patator': '#6f42c1',
        'SSH-Patator': '#ffc107',
        'Web Attack Brute Force': '#fd7e14',
        'Web Attack XSS': '#d63384',
        'Web Attack Sql Injection': '#0dcaf0',
        'Bot': '#343a40',
        'Infiltration': '#e83e8c',
        'DoS GoldenEye': '#dc3545',
        'DoS Hulk': '#8b0000',
        'DoS Slowhttptest': '#a52a2a',
        'DoS slowloris': '#cd5c5c',
        'DDoS': '#20c997',
        'Heartbleed': '#6610f2',
        'PortScan': '#17a2b8'
    }

    with col_left:
        st.subheader("Traffic Flow")
        if not df.empty:
            df_recent = df.tail(100)
            fig_line = px.line(df_recent, x=df_recent.index, y='prob_attack', color='label',
                               color_discrete_map=color_map, markers=True)
            
            fig_line.update_layout(paper_bgcolor="white", plot_bgcolor="white", font=dict(color="black"))
            fig_line.update_xaxes(showgrid=False)
            fig_line.update_yaxes(showgrid=True, gridcolor='#DEE2E6')
            st.plotly_chart(fig_line, use_container_width=True)

    with col_right:
        st.subheader("Attack Distribution")
        traffic_counts = df['label'].value_counts().reset_index()
        traffic_counts.columns = ['Type', 'Count']
        
        fig_pie = px.pie(traffic_counts, values='Count', names='Type', 
                     hole=0.5, color='Type', color_discrete_map=color_map)
        fig_pie.update_layout(showlegend=True, paper_bgcolor="white", font=dict(color="black"),
                              legend=dict(orientation="h", yanchor="bottom", y=-0.5, xanchor="center", x=0.5))
        st.plotly_chart(fig_pie, use_container_width=True)

    c_bot1, c_bot2 = st.columns([1, 2])
    
    with c_bot1:
        st.subheader("Top Attackers")
        if not attacks.empty:
            attacker_counts = attacks['source_ip'].value_counts().reset_index()
            attacker_counts.columns = ['Source IP', 'Attacks']
            
            fig_bar = px.bar(attacker_counts, x='Attacks', y='Source IP', orientation='h', 
                             color='Attacks', color_continuous_scale='Reds')
            fig_bar.update_layout(paper_bgcolor="white", plot_bgcolor="white", font=dict(color="black"))
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.success("No active attackers.")

    with c_bot2:
        st.subheader("Live Security Logs")
        st.dataframe(
            df.tail(15)[['timestamp', 'source_ip', 'label', 'prob_attack']].sort_index(ascending=False),
            use_container_width=True,
            column_config={
                "prob_attack": st.column_config.ProgressColumn(
                    "Confidence",
                    format="%.2f",
                    min_value=0,
                    max_value=1,
                ),
                "label": "Threat Type",
                "source_ip": "Attacker IP"
            }
        )

    time.sleep(1)
    st.rerun()