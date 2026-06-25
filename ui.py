"""
Streamlit UI for the Network Scanner.
"""

import streamlit as st
import pandas as pd
import json
import io
import socket
from scanner import NetworkScanner
from report import generate_report
from subnet_map import discover_subnet
from validation import ValidationError
from audit_log import AuditLogger

st.set_page_config(
    page_title="Network Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp {
        background: #f1f5f9;
    }
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 1.5rem;
    }
    .stButton>button {
        background-color: #2563eb;
        color: white;
        border-radius: 10px;
    }
    .stProgress>div {
        background: #dbeafe;
    }
    .stProgressBar>div {
        background: #2563eb;
    }
    .stMetric>div>div {
        background-color: #ffffff;
    }
    .scan-card {
        background: white;
        border-radius: 20px;
        padding: 24px;
        box-shadow: 0 15px 40px rgba(15, 23, 42, 0.08);
    }
    .scan-card h2,
    .scan-card h3 {
        margin-top: 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize audit logger
audit_logger = AuditLogger()

st.title("🔍 Network Scanner — Professional Edition")
st.markdown(
    "Streamlined vulnerability discovery for authorized systems only. Fast, responsive, and easy to use."
)

with st.sidebar:
    st.header("Scan Configuration")
    st.write("Configure your scan and start a safe audit of a target host.")
    with st.form(key="scan_form"):
        target = st.text_input("Target (IP or hostname)", placeholder="e.g. 127.0.0.1")

        scan_profile = st.selectbox(
            "Scan Profile",
            ["Common (1-1024)", "Quick (Top 20)", "Web (80, 443, 8080)", "Full (1-65535)", "Custom"],
            index=0
        )

        col1, col2 = st.columns(2)

        # Define common ports
        profile_map = {
            "Common (1-1024)": (None, 1, 1024),
            "Quick (Top 20)": ([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080], None, None),
            "Web (80, 443, 8080)": ([80, 443, 8080, 8443], None, None),
            "Full (1-65535)": (None, 1, 65535),
            "Custom": (None, 1, 1024)
        }

        selected_profile = profile_map.get(scan_profile)
        specific_ports = selected_profile[0]

        col1, col2 = st.columns(2)

        if specific_ports:
            st.info(f"Scanning {len(specific_ports)} specific ports: {', '.join(map(str, specific_ports[:10]))}{'...' if len(specific_ports) > 10 else ''}")
            start_port = 1
            end_port = 1
        else:
            with col1:
                start_port = st.number_input("Start Port", 1, 65535, selected_profile[1])
            with col2:
                end_port = st.number_input("End Port", 1, 65535, selected_profile[2])

        scan_type = st.radio("Protocol", ["tcp", "udp"], horizontal=True)
        grab_banners = st.checkbox("Grab service banners & versions", value=True)
        include_hints = st.checkbox("Include vulnerability hints", value=True)
        timeout = st.slider("Timeout (seconds)", 0.1, 5.0, 1.0, 0.1)
        max_threads = st.slider("Max Threads", 10, 500, 100, 10)
        scan_button = st.form_submit_button("🚀 Start Scan")

    st.markdown("---")
    st.warning(
        "⚠️ Only scan systems you own or have explicit written permission to test. "
        "Unauthorized scanning is illegal."
    )
    
    # Show audit stats in sidebar
    with st.expander("📊 Scan History Stats"):
        stats = audit_logger.get_stats()
        if stats:
            st.metric("Total Scans", stats.get("total_scans", 0))
            st.metric("Success Rate", f"{stats.get('success_rate', 0)}%")

if scan_button and not target:
    st.sidebar.error("Please enter a target before starting the scan.")

if "last_result" not in st.session_state:
    st.session_state["last_result"] = None

tab1, tab2 = st.tabs(["🎯 Single Target Scan", "🌐 Subnet Discovery"])

with tab1:
    with st.container():
        st.markdown("<div class='scan-card'>", unsafe_allow_html=True)
        st.subheader("Single Target Scan")
        st.write(
            "Launch a TCP or UDP scan against one host and review open services, banners, and security hints."
        )

        if scan_button and target:
            if start_port > end_port:
                st.error("Start port must be less than or equal to end port.")
            else:
                if (end_port - start_port) > 5000:
                    st.warning("Large port range selected. The scan may take longer.")

                scanner = NetworkScanner(
                    target=target,
                    start_port=int(start_port),
                    end_port=int(end_port),
                    timeout=timeout,
                    max_threads=int(max_threads),
                    scan_type=scan_type,
                    grab_banners=grab_banners,
                    include_hints=include_hints,
                    ports=specific_ports
                )

                progress_bar = st.progress(0)
                status_text = st.empty()

                def update_progress(scanned, total):
                    progress_bar.progress(scanned / total)
                    status_text.text(f"Scanning {scanned}/{total} ports...")

                with st.spinner("Running scan..."):
                    result = scanner.scan(progress_callback=update_progress)
                    if result:
                        audit_logger.log_scan(result)
                        st.session_state["last_result"] = result
        
        if st.session_state["last_result"]:
            result = st.session_state["last_result"]

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Target IP", result["ip"])
            c2.metric("Protocol", result["scan_type"])
            c3.metric("Open Ports", result["open_ports"])
            c4.metric("Duration", result["duration"])

            st.markdown("---")
            st.subheader("Scan Overview")

            # DNS Info
            with st.expander("🌐 Host & DNS Information"):
                c1, c2 = st.columns(2)
                try:
                    hostname, aliases, addresses = socket.gethostbyaddr(result["ip"])
                    c1.write(f"**Hostname:** {hostname}")
                    c1.write(f"**Aliases:** {', '.join(aliases) if aliases else 'None'}")
                    c2.write(f"**Addresses:** {', '.join(addresses)}")
                except Exception as e:
                    st.write(f"Could not retrieve DNS info: {e}")

            st.info(result["os"])

            if result["results"]:
                st.subheader("Open Ports")
                rows = []
                for r in result["results"]:
                    rows.append(
                        {
                            "Port": r["port"],
                            "Protocol": r["protocol"].upper(),
                            "State": r["state"].capitalize(),
                            "Service": r["service"],
                            "Banner": (r.get("banner") or "—")[:120],
                        }
                    )
                st.dataframe(rows, use_container_width=True)

                if include_hints:
                    st.subheader("Security Hints")
                    for r in result["results"]:
                        hints = r.get("hints", {})
                        if hints:
                            with st.expander(
                                f"Port {r['port']} — {hints.get('service', '')} "
                                f"(Risk: {hints.get('risk', '?')})"
                            ):
                                for hint in hints.get("hints", []):
                                    st.write(f"• {hint}")
            else:
                st.info("No open ports were detected in the scanned range.")

            st.markdown("---")
            st.subheader("Analysis & Export")

            # Add visualizations
            if result["results"]:
                col_chart1, col_chart2 = st.columns(2)

                with col_chart1:
                    st.write("**Services Found**")
                    service_counts = pd.DataFrame([r["service"] for r in result["results"]], columns=["Service"]).value_counts().reset_index()
                    service_counts.columns = ["Service", "Count"]
                    st.bar_chart(service_counts.set_index("Service"))

                with col_chart2:
                    st.write("**Risk Distribution**")
                    risks = [r.get("hints", {}).get("risk", "Low") for r in result["results"]]
                    risk_counts = pd.DataFrame(risks, columns=["Risk"]).value_counts().reset_index()
                    risk_counts.columns = ["Risk", "Count"]
                    st.bar_chart(risk_counts.set_index("Risk"))

            col_exp1, col_exp2, col_exp3 = st.columns(3)

            with col_exp1:
                if st.button("📄 Generate PDF Report", use_container_width=True):
                    path = generate_report(result)
                    with open(path, "rb") as f:
                        st.download_button(
                            label="⬇️ Download PDF",
                            data=f.read(),
                            file_name=f"scan_{result['ip']}.pdf",
                            mime="application/pdf",
                        )

            with col_exp2:
                # JSON Export
                json_data = json.dumps(result, indent=4)
                st.download_button(
                    label="⬇️ Download JSON",
                    data=json_data,
                    file_name=f"scan_{result['ip']}.json",
                    mime="application/json",
                    use_container_width=True
                )

            with col_exp3:
                # CSV Export
                if result["results"]:
                    df = pd.DataFrame(result["results"])
                    # Flatten hints for CSV if possible, or just drop
                    if "hints" in df.columns:
                        df["hints"] = df["hints"].apply(lambda x: "|".join(x.get("hints", [])) if x else "")
                    csv_data = df.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="⬇️ Download CSV",
                        data=csv_data,
                        file_name=f"scan_{result['ip']}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
        else:
            st.info("Use the sidebar to configure a scan and start the audit.")

        st.markdown("</div>", unsafe_allow_html=True)

with tab2:
    st.subheader("Subnet & Range Discovery")
    st.write(
        "Find live hosts in a subnet or range. This discovery mode uses TCP probing to identify reachable systems."
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        subnet_target = st.text_input(
            "Subnet or range",
            placeholder="e.g. 192.168.1.0/24 or 192.168.1.1-254",
            key="subnet_target",
        )
    with col2:
        subnet_threads = st.number_input("Threads", 10, 500, 100, key="subnet_threads")

    if st.button("🔎 Discover Hosts", key="discover_hosts"):
        if not subnet_target:
            st.error("Please enter a subnet or range.")
        else:
            progress = st.progress(0)
            status = st.empty()

            def subnet_progress(scanned, total, host):
                progress.progress(scanned / total)
                status.text(f"Probing {host} — {scanned}/{total}")

            with st.spinner("Discovering live hosts..."):
                live = discover_subnet(
                    subnet_target,
                    max_threads=int(subnet_threads),
                    progress_callback=subnet_progress,
                )

            progress.empty()
            status.empty()

            st.success(f"Found {len(live)} live host(s).")
            if live:
                st.dataframe(
                    [{"#": i + 1, "IP Address": item["ip"], "Hostname": item["hostname"]} for i, item in enumerate(live)],
                    use_container_width=True,
                )

                # Add a button to scan a discovered host
                selected_ip = st.selectbox("Select a host to scan in detail", [item["ip"] for item in live])
                if st.button("🔍 Scan Selected Host"):
                    st.info(f"Target set to {selected_ip}. Please go to 'Single Target Scan' and click 'Start Scan'.")
                    # We could also automatically switch tabs or trigger the scan,
                    # but for now let's just prompt the user.
            else:
                st.info("No live hosts were discovered in the provided range.")
