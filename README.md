# 🔍 Network Scanner — Personal Companion

A professional network scanning toolkit with a clean Streamlit UI.

## Features
- **Intelligent Scan Profiles** — Quick (Top 20), Web-focused, or Full 65k scans
- **TCP & UDP** port scanning (multi-threaded)
- **Banner grabbing** — reads actual service versions
- **Vulnerability hints** for ~20 common services
- **Subnet discovery** — find live hosts with reverse DNS resolution
- **Interactive Visualizations** — Service and Risk distribution charts
- **Multi-format Reports** — PDF, JSON, and CSV exports
- **Audit Logging** — maintains a history of all scans for compliance
- Clean web interface built with Streamlit

## ⚠️ Legal
Only scan systems you own or have explicit written permission to test.
Unauthorized scanning is illegal in most countries.

## Run Locally
```bash
pip install -r requirements.txt
streamlit run ui.py
```

## CLI Usage
You can run scans from the command line using the bundled CLI:

```bash
python cli.py TARGET --start 1 --end 1024 --protocol tcp --output report.pdf
```

Replace `TARGET` with an IP address or hostname (for example `127.0.0.1`).
