"""
Generate a professional PDF report of scan results.
"""

from datetime import datetime

try:
    from fpdf import FPDF
except ImportError as exc:
    raise ImportError(
        "The 'fpdf' package is required to generate PDF reports. "
        "Install it with: pip install fpdf2"
    ) from exc


class ScanReport(FPDF):
    def header(self):
        # Draw a clean, running page header (only on pages after page 1, or simple header on all)
        self.set_text_color(148, 163, 184)  # slate-400
        self.set_font("Helvetica", "B", 8)
        self.cell(0, 5, "NETWORK AUDIT REPORT  |  CONFIDENTIAL", ln=True, align="L")
        self.set_line_width(0.2)
        self.set_draw_color(226, 232, 240)
        self.line(10, 15, 200, 15)
        self.ln(5)

    def footer(self):
        # Position at 15 mm from bottom
        self.set_y(-15)
        self.set_line_width(0.2)
        self.set_draw_color(226, 232, 240)
        self.line(10, 285, 200, 285)  # standard A4 page height is 297mm
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        
        # Display page number
        self.cell(0, 10, f"Page {self.page_no()} of {{nb}}", align="R")


def generate_report(scan_data, output_path="network_scan_report.pdf"):
    """Generate a professional PDF report from scan results."""
    pdf = ScanReport()
    pdf.alias_nb_pages()  # Enables total page count placeholder {nb}
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # 1. Title Banner block
    pdf.set_fill_color(30, 58, 138)  # Deep Blue
    pdf.rect(10, 20, 190, 26, "F")
    
    pdf.set_y(23)
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 8, "   PORT SCAN & VULNERABILITY ASSESSMENT", ln=True, align="L")
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(0, 5, "    Target Host Vulnerability Audit Report", ln=True, align="L")
    pdf.ln(10)

    # 2. Metadata Grid
    pdf.set_text_color(15, 23, 42)  # dark blue/slate
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Assessment Metadata", ln=True)
    pdf.set_line_width(0.3)
    pdf.set_draw_color(30, 58, 138)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    pdf.set_font("Helvetica", "", 9)
    metadata = [
        ("Target Host:", scan_data.get('target', 'N/A'), "Scan Start:", scan_data.get('start_time', 'N/A')),
        ("IP Address:", scan_data.get('ip', 'N/A'), "Scan End:", scan_data.get('end_time', 'N/A')),
        ("Operating System:", scan_data.get('os', 'Unknown'), "Duration:", scan_data.get('duration', '0:00:00')),
        ("Scan Protocol:", scan_data.get('scan_type', 'TCP').upper(), "Open Ports Found:", str(scan_data.get('open_ports', 0))),
    ]
    
    pdf.set_draw_color(226, 232, 240)
    for row in metadata:
        # Col 1 Label
        pdf.set_fill_color(241, 245, 249)  # Light grey background
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(35, 7, f"  {row[0]}", border=1, fill=True)
        # Col 1 Value
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(60, 7, f" {row[1]}", border=1)
        # Col 2 Label
        pdf.set_fill_color(241, 245, 249)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(35, 7, f"  {row[2]}", border=1, fill=True)
        # Col 2 Value
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(60, 7, f" {row[3]}", border=1)
        pdf.ln()
    pdf.ln(6)

    # 3. Discovered Services & Ports Table
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Discovered Services & Open Ports", ln=True)
    pdf.set_line_width(0.3)
    pdf.set_draw_color(30, 58, 138)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    if scan_data.get("results"):
        # Header Row
        pdf.set_fill_color(30, 58, 138)
        pdf.set_text_color(255, 255, 255)
        pdf.set_draw_color(30, 58, 138)
        pdf.set_font("Helvetica", "B", 9)
        
        col_widths = [20, 25, 45, 100]
        headers = ["Port", "State", "Service", "Banner / Version Signature"]
        for i, h in enumerate(headers):
            pdf.cell(col_widths[i], 8, f" {h}", border=1, align="L", fill=True)
        pdf.ln()
        
        pdf.set_text_color(15, 23, 42)
        pdf.set_draw_color(226, 232, 240)
        pdf.set_font("Helvetica", "", 9)
        
        fill = False
        for r in scan_data["results"]:
            pdf.set_fill_color(248, 250, 252) if fill else pdf.set_fill_color(255, 255, 255)
            
            port_str = f" {r.get('port')}/{r.get('protocol', 'tcp').upper()}"
            state_str = f" {r.get('state', 'open').capitalize()}"
            service_str = f" {r.get('service', 'unknown')}"
            
            # Truncate version string to prevent horizontal text overflow
            raw_ver = r.get("parsed_version") or r.get("banner") or "—"
            raw_ver_cleaned = raw_ver.replace("\r", " ").replace("\n", " ").strip()
            ver_str = f" {raw_ver_cleaned[:65]}..." if len(raw_ver_cleaned) > 65 else f" {raw_ver_cleaned}"
            
            pdf.cell(col_widths[0], 7, port_str, border=1, fill=True)
            pdf.cell(col_widths[1], 7, state_str, border=1, fill=True)
            pdf.cell(col_widths[2], 7, service_str, border=1, fill=True)
            pdf.cell(col_widths[3], 7, ver_str, border=1, fill=True)
            pdf.ln()
            fill = not fill
    else:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 8, "No open ports were discovered during the scan.", ln=True)
    pdf.ln(6)

    # 4. Security Risk Analysis & Hints
    if pdf.get_y() > 230:
        pdf.add_page()
        
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Security Risk Analysis & Vulnerability Hints", ln=True)
    pdf.set_line_width(0.3)
    pdf.set_draw_color(30, 58, 138)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    has_hints = False
    for r in scan_data.get("results", []):
        hints = r.get("hints", {})
        if hints and hints.get("hints"):
            has_hints = True
            
            # Prevent single-item breaks across page boundaries
            if pdf.get_y() > 245:
                pdf.add_page()
                
            risk = hints.get("risk", "Low")
            # Select risk color
            if risk.capitalize() == "Critical":
                rc, gc, bc = (185, 28, 28)    # Red
            elif risk.capitalize() == "High":
                rc, gc, bc = (234, 88, 12)    # Orange
            elif risk.capitalize() == "Medium":
                rc, gc, bc = (202, 138, 4)    # Yellow/Amber
            else:
                rc, gc, bc = (22, 163, 74)    # Green
                
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(rc, gc, bc)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(20, 6, f" {risk.upper()} ", border=0, fill=True, align="C")
            
            pdf.set_text_color(15, 23, 42)
            pdf.cell(4)  # spacer
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"Port {r['port']} — {hints.get('service', 'Service')} Service Configuration", ln=True)
            
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(71, 85, 105)
            pdf.ln(1)
            for hint in hints.get("hints", []):
                # Custom bullet character
                pdf.set_text_color(rc, gc, bc)
                pdf.cell(8, 5, "  * ", ln=False)
                pdf.set_text_color(71, 85, 105)
                pdf.multi_cell(0, 5, hint)
            pdf.ln(2)
            
    if not has_hints:
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, "No security alerts triggered for this host configuration.", ln=True)
    pdf.ln(6)

    # 5. Disclaimer & Warnings
    if pdf.get_y() > 240:
        pdf.add_page()
        
    pdf.ln(4)
    # Shaded warning block
    pdf.set_fill_color(254, 242, 242)  # light red
    pdf.set_draw_color(252, 165, 165)  # red border
    pdf.rect(10, pdf.get_y(), 190, 24, "FDF")
    
    pdf.set_y(pdf.get_y() + 2)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(153, 27, 27)  # Dark Red
    pdf.cell(0, 5, "   WARNING & LEGAL DISCLAIMER", ln=True)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(127, 29, 29)
    pdf.multi_cell(
        0, 4.5, 
        "   This report contains results from an authorized network scanning audit. "
        "Unauthorized port scanning is illegal in most jurisdictions. "
        "This information should only be used to secure target systems and for approved educational compliance."
    )

    pdf.output(output_path)
    return output_path
