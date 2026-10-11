
import streamlit as st
import boto3
import pandas as pd
import plotly.express as px
from io import BytesIO

st.set_page_config(
    page_title="Cloud Security Analysis",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI, Cloud Computing and Big Data in Cybersecurity")
st.caption("Security log analysis dashboard | AWS S3 + Python + ML")

@st.cache_data(ttl=60)
def load_logs():
    s3 = boto3.client("s3")
    response = s3.get_object(
        Bucket="cloud-security-analysis",
        Key="security_logs.csv"
    )
    return pd.read_csv(BytesIO(response["Body"].read()))

try:
    df = load_logs()

    required = {"timestamp", "source_ip", "event_type"}
    if not required.issubset(df.columns):
        st.error("The CSV is missing one or more required columns.")
        st.stop()

    suspicious_types = [
        "Failed Login",
        "Port Scan",
        "Malware Alert",
        "Suspicious File"
    ]

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["potential_alert"] = df["event_type"].isin(suspicious_types)

    total = len(df)
    alert_count = int(df["potential_alert"].sum())
    unique_ips = df["source_ip"].nunique()

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Events", total)
    col2.metric("Potential Alert Events", alert_count)
    col3.metric("Unique Source IPs", unique_ips)

    st.subheader("Security Event Distribution")
    counts = (
        df["event_type"]
        .value_counts()
        .rename_axis("Event Type")
        .reset_index(name="Count")
    )

    st.plotly_chart(
        px.bar(
            counts,
            x="Event Type",
            y="Count",
            color="Event Type",
            title="Events by Category"
        ),
        use_container_width=True
    )

    st.subheader("Event Composition")
    st.plotly_chart(
        px.pie(
            counts,
            names="Event Type",
            values="Count",
            title="Share of Security Events"
        ),
        use_container_width=True
    )

    st.subheader("Potential Security Alerts")
    alerts = df[df["potential_alert"]]

    if alerts.empty:
        st.success("No potential alert events found.")
    else:
        st.dataframe(
            alerts.sort_values("timestamp", ascending=False),
            use_container_width=True
        )

    st.subheader("Filter Logs")
    event_options = sorted(df["event_type"].dropna().unique().tolist())
    selected = st.multiselect(
        "Choose event types",
        event_options,
        default=event_options
    )
    filtered = df[df["event_type"].isin(selected)]
    st.dataframe(filtered, use_container_width=True)

    st.download_button(
        "Download Filtered Logs as CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="filtered_security_logs.csv",
        mime="text/csv"
    )

    st.info(
        "This project uses simulated security logs. "
        "Potential alerts are rule-based examples, not confirmed attacks. "
        "The ML demonstration is a separate component."
    )

except Exception as e:
    st.error(f"Could not load logs from AWS S3: {e}")
    st.caption(
        "Check your AWS CLI credentials, S3 permissions, bucket name, "
        "and uploaded CSV file."
    )
