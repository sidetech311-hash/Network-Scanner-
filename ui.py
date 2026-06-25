"""
Streamlit UI for the Network Scanner.
"""

import streamlit as st
import pandas as pd
import json
import io
import socket
import os
from pathlib import Path
import altair as alt

from scanner import NetworkScanner
from report import generate_report
from subnet_map import discover_subnet
from validation import ValidationError
from audit_log import AuditLogger
from scheduler import ScanScheduler
from ssh_audit import SSHAuditor

st.set_page_config(
    page_title="Network Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for rich aesthetics and clean spacing
st.markdown(
    """
    <style>
    .stApp {
        background: #f8fafc;
    }
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 1.5rem;
    }
    .stButton>button {
        background-color: #2563eb;
        color: white;
        border-radius: 10px;
        font-weight: 600;
        transition: all 0.2s ease-in-out;
    }
    .stButton>button:hover {
        background-color: #1d4ed8;
        transform: translateY(-1px);
    }
    .stProgress>div {
        background: #e2e8f0;
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
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.04);
        margin-bottom: 20px;
        border: 1px solid #e2e8f0;
    }
    .scan-card h2,
    .scan-card h3 {
        margin-top: 0;
        color: #0f172a;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize audit logger and scheduler background thread
audit_logger = AuditLogger()
scheduler = ScanScheduler()
scheduler.start()

# Initialize session state for target selection from subnet discovery
if "target_ip" not in st.session_state:
    st.session_state["target_ip"] = ""

st.title("🔍 Network Scanner — Professional Edition")
st.markdown(
    "Streamlined vulnerability discovery and network audits for authorized systems. Fast, responsive, and compliance-ready."
)

with st.sidebar:
    st.header("Scan Configuration")
    st.write("Configure scan parameters and launch a security audit.")
    with st.form(key="scan_form"):
        target = st.text_input(
            "Target (IP or hostname)", 
            value=st.session_state["target_ip"], 
            placeholder="e.g. 127.0.0.1"
        )

        scan_profile = st.selectbox(
            "Scan Profile",
            ["Common (1-1024)", "Quick (Top 20)", "Web (80, 443, 8080)", "Full (1-65535)", "Custom"],
            index=0
        )

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
            st.info(f"Scanning {len(specific_ports)} selected ports: {', '.join(map(str, specific_ports[:10]))}{'...' if len(specific_ports) > 10 else ''}")
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
        use_async = st.checkbox("High-Speed Async Scan (TCP only)", value=True)
        
        timeout = st.slider("Timeout (seconds)", 0.1, 5.0, 1.0, 0.1)
        max_threads = st.slider("Max Threads / Concurrency", 10, 1000, 100, 10)
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

# Configure Tabs
tabs_list = ["🎯 Single Target Scan", "🌐 Subnet Discovery", "📊 History & Analytics", "⏰ Scan Scheduler", "🔑 Credentialed SSH Audit"]
tab1, tab2, tab3, tab4, tab5 = st.tabs(tabs_list)

with tab1:
    with st.container():
        st.markdown("<div class='scan-card'>", unsafe_allow_html=True)
        st.subheader("Single Target Port Scan")
        st.write(
            "Launch a multi-threaded or asynchronous TCP/UDP scan against a single host to discover open services, versions, and security vulnerabilities."
        )

        if scan_button and target:
            # Sync session state to target input just in case
            st.session_state["target_ip"] = target
            if not specific_ports and start_port > end_port:
                st.error("Start port must be less than or equal to end port.")
            else:
                if not specific_ports and (end_port - start_port) > 5000:
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
                    ports=specific_ports,
                    use_async=use_async
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

            st.info(f"**Detected OS:** {result['os']}")

            if result["results"]:
                st.subheader("Open Ports & Services")
                rows = []
                for r in result["results"]:
                    rows.append(
                        {
                            "Port": r["port"],
                            "Protocol": r["protocol"].upper(),
                            "State": r["state"].capitalize(),
                            "Service": r["service"],
                            "Banner / Version": (r.get("banner") or "—")[:120],
                        }
                    )
                st.dataframe(rows, use_container_width=True, hide_index=True)

                if include_hints:
                    st.subheader("Security Remediation Hints")
                    for r in result["results"]:
                        hints = r.get("hints", {})
                        if hints and hints.get("hints"):
                            risk_val = hints.get("risk", "Low")
                            # Map risk tag colors
                            if risk_val.capitalize() == "Critical":
                                color_style = "color:#ef4444; font-weight:bold;"
                            elif risk_val.capitalize() == "High":
                                color_style = "color:#f97316; font-weight:bold;"
                            elif risk_val.capitalize() == "Medium":
                                color_style = "color:#eab308; font-weight:bold;"
                            else:
                                color_style = "color:#22c55e; font-weight:bold;"
                                
                            with st.expander(
                                f"Port {r['port']} — {hints.get('service', '')} (Risk: {risk_val})"
                            ):
                                st.markdown(f"**Risk Level:** <span style='{color_style}'>{risk_val.upper()}</span>", unsafe_allow_html=True)
                                for hint in hints.get("hints", []):
                                    st.write(f"• {hint}")
            else:
                st.info("No open ports were detected in the scanned range.")

            st.markdown("---")
            st.subheader("Analysis & Export")

            # Add visualizations using Altair
            if result["results"]:
                col_chart1, col_chart2 = st.columns(2)

                with col_chart1:
                    st.write("**Services Found**")
                    service_counts = pd.DataFrame([r["service"] for r in result["results"]], columns=["Service"]).value_counts().reset_index()
                    service_counts.columns = ["Service", "Count"]
                    
                    chart_services = alt.Chart(service_counts).mark_bar(
                        cornerRadiusTopLeft=4,
                        cornerRadiusTopRight=4
                    ).encode(
                        x=alt.X("Service:N", sort="-y", title="Service Name"),
                        y=alt.Y("Count:Q", title="Number of Ports", axis=alt.Axis(tickMinStep=1)),
                        color=alt.value("#2563eb")
                    ).properties(height=260)
                    st.altair_chart(chart_services, use_container_width=True)

                with col_chart2:
                    st.write("**Risk Distribution**")
                    risks = [r.get("hints", {}).get("risk", "Low") for r in result["results"]]
                    risk_counts = pd.DataFrame(risks, columns=["Risk"]).value_counts().reset_index()
                    risk_counts.columns = ["Risk", "Count"]
                    
                    color_scale = alt.Scale(
                        domain=["Low", "Medium", "High", "Critical"],
                        range=["#22c55e", "#eab308", "#f97316", "#ef4444"]
                    )
                    
                    chart_risks = alt.Chart(risk_counts).mark_bar(
                        cornerRadiusTopLeft=4,
                        cornerRadiusTopRight=4
                    ).encode(
                        x=alt.X("Risk:N", sort=["Low", "Medium", "High", "Critical"], title="Risk Level"),
                        y=alt.Y("Count:Q", title="Count", axis=alt.Axis(tickMinStep=1)),
                        color=alt.Color("Risk:N", scale=color_scale, legend=None)
                    ).properties(height=260)
                    st.altair_chart(chart_risks, use_container_width=True)

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
        "Scan an entire local network range using fast host probes to identify active hosts."
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        subnet_target = st.text_input(
            "Subnet or range",
            placeholder="e.g. 192.168.1.0/24 or 192.168.1.1-254",
            key="subnet_target_input",
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
                st.session_state["discovered_hosts"] = live
            else:
                st.session_state["discovered_hosts"] = []
                st.info("No live hosts were discovered in the provided range.")

    if "discovered_hosts" in st.session_state and st.session_state["discovered_hosts"]:
        live = st.session_state["discovered_hosts"]
        st.dataframe(
            [{"#": i + 1, "IP Address": item["ip"], "Hostname": item["hostname"]} for i, item in enumerate(live)],
            use_container_width=True,
        )

        # Quick select target
        selected_ip = st.selectbox(
            "Select a host to target for port scanning", 
            [item["ip"] for item in live],
            key="discovered_host_select"
        )
        if st.button("🎯 Load as Active Scan Target"):
            st.session_state["target_ip"] = selected_ip
            st.success(f"Target host set to {selected_ip}! Go to the 'Single Target Scan' tab and click 'Start Scan' to begin.")
            st.rerun()

with tab3:
    st.subheader("Historical Scans & Comparative Analysis")
    st.write(
        "View past audit logs, manage saved results, and compare scans side-by-side to track security changes (drift detection)."
    )

    # Load history from audit logger
    history = audit_logger.get_history(limit=200)
    
    if not history:
        st.info("No audit logs found. Run a target scan to generate history logs.")
    else:
        df_history = pd.DataFrame(history)
        
        # Reverse rows to show newest first
        df_history_display = df_history.iloc[::-1].copy()
        
        # Display history in Streamlit
        col_map = {
            "timestamp": "Timestamp",
            "target": "Target Name",
            "ip": "IP Address",
            "scan_type": "Protocol",
            "port_range": "Port Range",
            "open_ports_count": "Open Ports",
            "duration": "Duration",
            "os_detected": "OS Detected",
            "status": "Status"
        }
        avail_cols = [c for c in col_map.keys() if c in df_history_display.columns]
        df_history_display = df_history_display[avail_cols].rename(columns=col_map)
        
        # Search filter
        search_filter = st.text_input("🔍 Filter logs by host IP or name", placeholder="Type to filter...")
        if search_filter:
            df_history_display = df_history_display[
                df_history_display["Target Name"].str.contains(search_filter, case=False, na=False) |
                df_history_display["IP Address"].str.contains(search_filter, case=False, na=False)
            ]
            
        st.dataframe(df_history_display, use_container_width=True, hide_index=True)
        
        col_act1, col_act2 = st.columns(2)
        
        with col_act1:
            st.subheader("🗑️ Delete Records")
            selected_ts = st.selectbox(
                "Select a scan timestamp to delete",
                options=df_history_display["Timestamp"].tolist() if not df_history_display.empty else ["None"]
            )
            
            if st.button("Confirm Delete") and selected_ts != "None":
                # Find matching row in history list to identify JSON file
                json_to_delete = ""
                matching_row = next((r for r in history if r["timestamp"] == selected_ts), None)
                if matching_row:
                    notes_field = matching_row.get("notes", "")
                    if "|" in notes_field:
                        parts = notes_field.split("|")
                        if len(parts) > 1 and parts[1].endswith(".json"):
                            json_to_delete = parts[1]
                    elif notes_field.endswith(".json"):
                        json_to_delete = notes_field
                        
                if audit_logger.delete_scan(selected_ts):
                    st.success(f"Scan deleted successfully!")
                    st.rerun()
                else:
                    st.error("Delete operation failed.")
                    
        with col_act2:
            st.subheader("📊 Comparative Audit (Drift)")
            scans_dir = Path("scans")
            json_files = []
            if scans_dir.exists():
                json_files = sorted(list(scans_dir.glob("*.json")), key=os.path.getmtime, reverse=True)
                
            if len(json_files) < 2:
                st.info("At least two detailed scans must be saved to perform comparative analysis.")
            else:
                # Load metadata for selectboxes
                options = []
                for f in json_files:
                    try:
                        with open(f, "r") as jf:
                            data = json.load(jf)
                            lbl = f"{data.get('target')} ({data.get('ip')}) — {data.get('start_time')}"
                            options.append((f.name, lbl))
                    except Exception:
                        pass
                
                if len(options) >= 2:
                    scan_a = st.selectbox("Baseline Scan (A)", [opt[0] for opt in options], format_func=lambda x: next(opt[1] for opt in options if opt[0] == x))
                    # Remove Scan A from second options list
                    options_b = [opt for opt in options if opt[0] != scan_a]
                    scan_b = st.selectbox("Comparison Scan (B)", [opt[0] for opt in options_b], format_func=lambda x: next(opt[1] for opt in options_b if opt[0] == x))
                    
                    if st.button("Compute Port Diff"):
                        data_a = audit_logger.get_detailed_scan(scan_a)
                        data_b = audit_logger.get_detailed_scan(scan_b)
                        
                        if data_a and data_b:
                            st.markdown("---")
                            st.write(f"### Port and Service Drift Analysis")
                            st.info(f"**Scan A (Baseline):** {data_a.get('target')} ({data_a.get('start_time')})  \n"
                                    f"**Scan B (Newer):** {data_b.get('target')} ({data_b.get('start_time')})")
                            
                            ports_a = {r["port"]: r for r in data_a.get("results", [])}
                            ports_b = {r["port"]: r for r in data_b.get("results", [])}
                            
                            all_ports = sorted(list(set(ports_a.keys()) | set(ports_b.keys())))
                            
                            diffs = []
                            for p in all_ports:
                                in_a = p in ports_a
                                in_b = p in ports_b
                                
                                if in_a and in_b:
                                    status = "Unchanged (Open in both)"
                                    svc = ports_b[p].get("service")
                                    detail = "Service banners match" if ports_a[p].get("banner") == ports_b[p].get("banner") else f"Banner drift: A='{ports_a[p].get('banner') or ''}', B='{ports_b[p].get('banner') or ''}'"
                                    diffs.append({"Port": p, "Service": svc, "Status": status, "Detail": detail})
                                elif in_a and not in_b:
                                    status = "🔴 Secured (Closed in newer scan)"
                                    svc = ports_a[p].get("service")
                                    diffs.append({"Port": p, "Service": svc, "Status": status, "Detail": "Port is no longer open"})
                                elif not in_a and in_b:
                                    status = "⚠️ Exposed (New open port)"
                                    svc = ports_b[p].get("service")
                                    diffs.append({"Port": p, "Service": svc, "Status": status, "Detail": f"New port open! Banner: {ports_b[p].get('banner') or '—'}"})
                                    
                            if diffs:
                                df_diff = pd.DataFrame(diffs)
                                st.dataframe(df_diff, use_container_width=True, hide_index=True)
                                
                                new_exposures = sum(1 for d in diffs if "Exposed" in d["Status"])
                                closed_ports = sum(1 for d in diffs if "Secured" in d["Status"])
                                
                                c_m1, c_m2 = st.columns(2)
                                c_m1.metric("New Exposures", new_exposures, delta=new_exposures, delta_color="inverse")
                                c_m2.metric("Ports Secured", closed_ports, delta=closed_ports)
                                
                                if new_exposures > 0:
                                    st.warning(f"⚠️ **Attention Required:** {new_exposures} new service port(s) are open in Scan B that were closed in Scan A. Verify this is authorized configuration drift.")
                                else:
                                    st.success("✅ **Drift Audit Clear:** No new ports exposed in comparison scan.")
                            else:
                                st.info("Both scans have identical open ports and service signatures.")
                        else:
                            st.error("Error loading scan data files.")

with tab4:
    st.subheader("⏰ Scan Scheduler")
    st.write(
        "Automate your security reviews. Add targets to be scanned periodically in the background."
    )
    
    col_sch1, col_sch2 = st.columns([1, 2])
    
    with col_sch1:
        st.write("#### Add New Schedule")
        with st.form(key="scheduler_form"):
            sch_target = st.text_input(
                "Target Host", 
                value=st.session_state["target_ip"], 
                placeholder="e.g. 127.0.0.1"
            )
            sch_profile = st.selectbox(
                "Scan Profile",
                ["Common (1-1024)", "Quick (Top 20)", "Web (80, 443, 8080)", "Full (1-65535)"]
            )
            sch_proto = st.radio("Protocol", ["tcp", "udp"], horizontal=True)
            sch_interval = st.number_input("Interval (Minutes)", min_value=1, max_value=43200, value=60)
            
            add_sch_button = st.form_submit_button("➕ Schedule Scan")
            
        if add_sch_button:
            if not sch_target:
                st.error("Please enter a target host.")
            else:
                scheduler.add_schedule(sch_target, sch_profile, sch_proto, sch_interval)
                st.success(f"Scheduled scan for {sch_target} created!")
                st.rerun()
                
    with col_sch2:
        st.write("#### Active Scan Schedules")
        schedules = scheduler.load_schedules()
        
        if not schedules:
            st.info("No active scan schedules defined.")
        else:
            sch_rows = []
            for s in schedules:
                sch_rows.append({
                    "ID": s["id"],
                    "Target": s["target"],
                    "Profile": s["profile"],
                    "Protocol": s["protocol"].upper(),
                    "Interval (Mins)": s["interval_mins"],
                    "Last Run": s.get("last_run", "Never"),
                    "Next Run": s.get("next_run", "Pending"),
                    "Status": "Active" if s.get("active", True) else "Disabled"
                })
            df_sch = pd.DataFrame(sch_rows)
            st.dataframe(df_sch.drop(columns=["ID"]), use_container_width=True, hide_index=True)
            
            # Action controls for existing schedules
            sch_action_col1, sch_action_col2 = st.columns(2)
            with sch_action_col1:
                target_sch_id = st.selectbox(
                    "Select schedule to toggle/delete", 
                    options=df_sch["ID"].tolist(),
                    format_func=lambda x: next(f"{r['Target']} ({r['Profile']})" for r in sch_rows if r["ID"] == x)
                )
            with sch_action_col2:
                sch_act_col1, sch_act_col2 = st.columns(2)
                with sch_act_col1:
                    if st.button("Enable/Disable", use_container_width=True):
                        scheduler.toggle_schedule(target_sch_id)
                        st.rerun()
                with sch_act_col2:
                    if st.button("🗑️ Delete Schedule", use_container_width=True):
                        scheduler.delete_schedule(target_sch_id)
                        st.rerun()
                        
        st.markdown("---")
        with st.expander("📝 Scheduler Activity Log"):
            if scheduler.activity_log:
                for log_msg in reversed(scheduler.activity_log):
                    st.text(log_msg)
            else:
                st.text("No scheduler activity registered yet.")

with tab5:
    st.subheader("🔑 Credentialed SSH Compliance Auditor")
    st.write(
        "Connect to a remote Linux target via SSH to audit local port bindings, check installed packages, and generate CVE vulnerability warnings."
    )
    
    col_ssh1, col_ssh2 = st.columns([1, 2])
    
    with col_ssh1:
        st.write("#### SSH Credentials")
        ssh_host = st.text_input("SSH Host IP", value=st.session_state["target_ip"], placeholder="e.g. 192.168.1.50")
        ssh_port = st.number_input("SSH Port", min_value=1, max_value=65535, value=22)
        ssh_user = st.text_input("Username", value="root")
        ssh_auth_method = st.radio("Authentication Method", ["Password", "Private Key"])
        
        ssh_pass = None
        pkey_val = None
        
        if ssh_auth_method == "Password":
            ssh_pass = st.text_input("Password", type="password")
        else:
            col_pk1, col_pk2 = st.columns([2, 1])
            with col_pk1:
                pkey_file = st.file_uploader("Upload Private Key (e.g. id_rsa)", type=None)
                if pkey_file:
                    pkey_val = pkey_file.read().decode("utf-8")
            with col_pk2:
                ssh_pass = st.text_input("Key Passphrase (optional)", type="password")
                
        run_audit_button = st.button("🚀 Run Credentialed SSH Audit", use_container_width=True)
        
    with col_ssh2:
        st.write("#### Audit Results")
        if run_audit_button:
            if not ssh_host:
                st.error("Please enter an SSH host IP.")
            else:
                auditor = SSHAuditor(
                    host=ssh_host,
                    port=ssh_port,
                    username=ssh_user,
                    password=ssh_pass,
                    pkey_content=pkey_val
                )
                
                with st.spinner("Connecting and executing internal compliance audit..."):
                    audit_res = auditor.run_audit()
                    
                if not audit_res.get("success"):
                    st.error(audit_res.get("error", "Audit failed."))
                else:
                    st.success(f"Audit completed successfully for {ssh_host}!")
                    
                    # 1. System Info
                    st.markdown("### 🐧 System Information")
                    os_data = audit_res.get("os_info", {})
                    if os_data:
                        sys_grid = []
                        for k, v in os_data.items():
                            sys_grid.append({"Property": k, "Value": v})
                        st.dataframe(pd.DataFrame(sys_grid), use_container_width=True, hide_index=True)
                    else:
                        st.info("No os-release or uname data gathered.")
                        
                    # 2. Compliance Warnings
                    st.markdown("### ⚠️ Compliance & Vulnerability Warnings")
                    warns = audit_res.get("warnings", [])
                    if warns:
                        for w in warns:
                            if "CRITICAL" in w:
                                st.error(w)
                            elif "HIGH" in w:
                                st.warning(w)
                            else:
                                st.info(w)
                    else:
                        st.success("No critical warnings triggered based on package versions or wildcard bindings.")
                        
                    # 3. Listening Ports
                    st.markdown("### 🔏 Internal Listening Ports")
                    l_ports = audit_res.get("listening_ports", [])
                    if l_ports:
                        st.dataframe(pd.DataFrame(l_ports), use_container_width=True, hide_index=True)
                    else:
                        st.info("No internal listening ports identified.")
                        
                    # 4. Installed Packages
                    st.markdown("### 📦 Installed Software Packages")
                    pkgs = audit_res.get("packages", [])
                    if pkgs:
                        df_pkgs = pd.DataFrame(pkgs)
                        pkg_search = st.text_input("🔍 Filter installed packages", placeholder="Type package name...")
                        if pkg_search:
                            df_pkgs = df_pkgs[df_pkgs["name"].str.contains(pkg_search, case=False, na=False)]
                        st.dataframe(df_pkgs, use_container_width=True, hide_index=True)
                    else:
                        st.info("No packages query results (requires dpkg or rpm on target).")
        else:
            st.info("Configure credentials and run the SSH compliance audit to analyze the target host internally.")
