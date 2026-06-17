import streamlit as st
import json
import ollama
from tools.virustotal import check_ip, check_hash, check_domain
from tools.abuseipdb import check_ip_abuse

# Page config
st.set_page_config(
    page_title="SOAR Agent Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Title
st.title("🛡️ AI-Powered SOAR Dashboard")
st.caption("Autonomous SOC analyst — powered by Mistral + VirusTotal + AbuseIPDB")

# Divider
st.divider()

# Sidebar — IOC input
st.sidebar.title("🔍 Investigate IOC")
st.sidebar.caption("Submit an indicator for analysis")

ioc_type = st.sidebar.selectbox(
    "IOC Type",
    ["IP Address", "File Hash", "Domain"]
)

ioc_value = st.sidebar.text_input("IOC Value", placeholder="e.g. 185.220.101.47")

investigate_btn = st.sidebar.button("🚀 Investigate", use_container_width=True)

# Sidebar — Alert simulator
st.sidebar.divider()
st.sidebar.title("⚡ Alert Simulator")

alert_type = st.sidebar.selectbox(
    "Alert Type",
    [
        "Suspicious outbound connection",
        "Brute force attempt",
        "Malware hash detected",
        "C2 beacon detected"
    ]
)

src_ip = st.sidebar.text_input("Source IP", value="192.168.1.42")
dst_ip = st.sidebar.text_input("Destination IP", value="185.220.101.47")

simulate_btn = st.sidebar.button("⚡ Run Agent", use_container_width=True)

# Main area — metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Alerts Today", "14", delta="3 new")
with col2:
    st.metric("Critical", "3", delta=None)
with col3:
    st.metric("Investigated", "11", delta=None)
with col4:
    st.metric("Avg Triage Time", "4m 12s", delta="-61%")

st.divider()

# IOC Investigation results
if investigate_btn and ioc_value:
    st.subheader(f"🔍 IOC Investigation — {ioc_value}")

    with st.spinner("Querying threat intel APIs..."):
        vt_result = None
        abuse_result = None

        if ioc_type == "IP Address":
            vt_result = check_ip(ioc_value)
            abuse_result = check_ip_abuse(ioc_value)
        elif ioc_type == "File Hash":
            vt_result = check_hash(ioc_value)
        elif ioc_type == "Domain":
            vt_result = check_domain(ioc_value)

    # Show results in columns
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**VirusTotal Results**")
        if "error" in vt_result:
            st.error(f"VirusTotal: {vt_result['error']}")
        else:
            verdict = vt_result.get("verdict", "UNKNOWN")
            if verdict == "MALICIOUS":
                st.error(f"🔴 Verdict: {verdict}")
            else:
                st.success(f"🟢 Verdict: {verdict}")

            st.json(vt_result)

    with col2:
        if abuse_result:
            st.markdown("**AbuseIPDB Results**")
            if "error" in abuse_result:
                st.error(f"AbuseIPDB: {abuse_result['error']}")
            else:
                score = abuse_result.get("abuse_score", 0)
                if score > 50:
                    st.error(f"🔴 Abuse Score: {score}/100")
                else:
                    st.success(f"🟢 Abuse Score: {score}/100")

                st.json(abuse_result)

    # AI analysis
    st.markdown("**🤖 AI Analysis**")
    with st.spinner("AI reasoning over results..."):
        prompt = f"""You are a SOC analyst. Analyze this threat intel and give a 3 sentence verdict.
IOC: {ioc_value}
VirusTotal: {json.dumps(vt_result)}
AbuseIPDB: {json.dumps(abuse_result) if abuse_result else 'N/A'}
Give a severity score out of 10 and recommend one action."""

        response = ollama.chat(
            model="mistral",
            options={"num_ctx": 512},
            messages=[{"role": "user", "content": prompt}]
        )
        st.info(response["message"]["content"])

# Agent simulation results
if simulate_btn:
    st.subheader(f"⚡ Agent Investigation — {alert_type}")

    alert = {
        "type": alert_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "port": 443,
        "repeat_count": 24
    }

    st.markdown("**Alert received:**")
    st.json(alert)

    # Run enrichment
    with st.spinner("Running threat intel lookups..."):
        vt_result = check_ip(dst_ip)
        abuse_result = check_ip_abuse(dst_ip)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**VirusTotal**")
        if "error" not in vt_result:
            if vt_result["verdict"] == "MALICIOUS":
                st.error(f"🔴 {vt_result['verdict']}")
            else:
                st.success(f"🟢 {vt_result['verdict']}")
        st.json(vt_result)

    with col2:
        st.markdown("**AbuseIPDB**")
        if "error" not in abuse_result:
            score = abuse_result["abuse_score"]
            if score > 50:
                st.error(f"🔴 Abuse Score: {score}/100")
            else:
                st.success(f"🟢 Abuse Score: {score}/100")
        st.json(abuse_result)

    # AI verdict
    st.markdown("**🤖 AI Verdict**")
    with st.spinner("AI generating verdict..."):
        prompt = f"""You are a SOC analyst. Given this alert and threat intel, give a verdict in 3 sentences with a severity score out of 10.
Alert: {json.dumps(alert)}
VirusTotal: {json.dumps(vt_result)}
AbuseIPDB: {json.dumps(abuse_result)}"""

        response = ollama.chat(
            model="mistral",
            options={"num_ctx": 512},
            messages=[{"role": "user", "content": prompt}]
        )

        verdict_text = response["message"]["content"]
        st.warning(verdict_text)

    # Recommended actions
    st.markdown("**📋 Recommended Actions**")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.button("🚫 Block IP", use_container_width=True)
    with col2:
        st.button("🔒 Isolate Host", use_container_width=True)
    with col3:
        st.button("📄 Generate Report", use_container_width=True)