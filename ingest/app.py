
import streamlit as st

st.set_page_config(
    page_title="LedgerSentinel AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ LedgerSentinel AI")
st.subheader("Financial Integrity & Cybersecurity Monitoring")

st.success("System initialized successfully!")

col1, col2, col3 = st.columns(3)

col1.metric("Transactions Monitored", 0)
col2.metric("Suspicious Transactions", 0)
col3.metric("Security Alerts", 0)

st.divider()

st.header("Financial Transaction Monitoring")
st.info("Transaction analysis coming soon.")

st.header("AI Fraud Detection")
st.info("Machine learning model not yet connected.")

st.header("Cybersecurity Monitoring")
st.info("Transaction integrity checks coming soon.")
