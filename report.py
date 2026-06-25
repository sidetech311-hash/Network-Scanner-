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
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 10, "Network Scan Report", ln=True, align="C")
        self.set_font("Helvetica", "", 10)
        self.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        self.ln(5)
        self.set_line_width(0.4)
        self.line(10, 28, 200, 28)
        self.ln(8)

    def footer(self):
        self.set_y(-20)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def add_section(self, title, content):
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 8, title, ln=True)
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 6, content)
        self.ln(3)

    def add_table(self, data, headers):
        self.set_font("Helvetica", "B", 10)
        col_widths = [20, 25, 55, 80]
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 8, header, border=1, align="C")
        self.ln()
        self.set_font("Helvetica", "", 10)

        for row in data:
            self.cell(col_widths[0], 8, str(row[0]), border=1)
            self.cell(col_widths[1], 8, str(row[1]), border=1)
            self.cell(col_widths[2], 8, str(row[2]), border=1)
            self.multi_cell(col_widths[3], 8, str(row[3]), border=1)


def generate_report(scan_data, output_path="network_scan_report.pdf"):
    """Generate a PDF report from scan results."""
    pdf = ScanReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.add_section(
        "Scan Information",
        f"Target: {scan_data['target']}\n"
        f"IP Address: {scan_data['ip']}\n"
        f"Detected OS: {scan_data['os']}\n"
        f"Scan Started: {scan_data['start_time']}\n"
        f"Scan Completed: {scan_data['end_time']}\n"
        f"Duration: {scan_data['duration']}\n"
        f"Open Ports Found: {scan_data['open_ports']}",
    )

    if scan_data["results"]:
        table_data = [
            (
                r["port"],
                r["state"].capitalize(),
                r["service"],
                (r.get("parsed_version") or r.get("banner") or "-")[:120],
            )
            for r in scan_data["results"]
        ]
        pdf.add_section("Open Port Summary", "The table below lists discovered open services, banners, and parsed software versions.")
        pdf.add_table(table_data, ["Port", "State", "Service", "Version/Banner"])

        hints_text = []
        for r in scan_data["results"]:
            hints = r.get("hints", {})
            if hints:
                hint_lines = [f"Port {r['port']} - {hints.get('service', '')} (Risk: {hints.get('risk', '?')})"]
                hint_lines.extend([f"- {hint}" for hint in hints.get("hints", [])])
                hints_text.append("\n".join(hint_lines))
        if hints_text:
            pdf.add_section("Vulnerability Hints", "\n\n".join(hints_text))
    else:
        pdf.add_section("Open Port Summary", "No open ports were found in the scanned range.")

    pdf.add_section(
        "Recommendations",
        "Review any unexpected open services promptly and verify that the target host is authorized for scanning. "
        "Use this report only for educational and permitted security testing."
    )

    pdf.add_section(
        "Disclaimer",
        "This report was generated for educational and authorized testing purposes only. "
        "Unauthorized scanning of networks is illegal."
    )

    pdf.output(output_path)
    return output_path
