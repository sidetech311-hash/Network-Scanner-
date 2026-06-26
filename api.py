import os
import tempfile
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import List, Optional

# Import scanner modules
from scanner import NetworkScanner
from ssl_auditor import audit_ssl_tls
from dir_buster import bust_directory
from report import generate_report

app = FastAPI(
    title="Network Scanner & Vulnerability Assessment API",
    description="A professional, developer-friendly REST API for network scanning, SSL configuration auditing, and directory exposure checks.",
    version="1.0.0"
)

# Request and Response Models
class PortScanResult(BaseModel):
    port: int
    state: str
    protocol: str
    service: str
    banner: Optional[str] = None
    cves: Optional[List[dict]] = None
    hints: Optional[List[str]] = None

class ScanResponse(BaseModel):
    target: str
    ip: Optional[str] = None
    scan_type: str
    start_port: int
    end_port: int
    duration_seconds: float
    os_detected: str
    open_ports: List[PortScanResult]

@app.get("/")
def read_root():
    return {
        "status": "online",
        "message": "Welcome to the Network Scanner API. Go to /docs for API documentation.",
        "documentation": "/docs"
    }

@app.get("/api/scan", response_model=ScanResponse)
def run_port_scan(
    target: str = Query(..., description="Target hostname or IP address"),
    start_port: int = Query(1, ge=1, le=65535, description="Starting port number"),
    end_port: int = Query(1024, ge=1, le=65535, description="Ending port number"),
    protocol: str = Query("tcp", description="Scan protocol: 'tcp' or 'udp'"),
    use_async: bool = Query(True, description="Enable high-speed asynchronous scanning"),
    grab_banners: bool = Query(True, description="Enable service banner grabbing and CVE mapping"),
    max_threads: int = Query(100, ge=1, le=1000, description="Maximum concurrent scan threads/semaphore limit"),
    timeout: float = Query(1.0, ge=0.1, le=5.0, description="Connection timeout in seconds")
):
    """
    Scans a target for open ports, detects active services, grabs banners,
    and maps service versions to known CVE vulnerabilities.
    """
    if start_port > end_port:
        raise HTTPException(status_code=400, detail="start_port must be less than or equal to end_port")

    try:
        scanner = NetworkScanner(
            target=target,
            start_port=start_port,
            end_port=end_port,
            timeout=timeout,
            max_threads=max_threads,
            scan_type=protocol.lower(),
            grab_banners=grab_banners,
            include_hints=True,
            use_async=use_async
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    ip = scanner.resolve_target()
    if not ip:
        raise HTTPException(status_code=404, detail=f"Could not resolve host: {target}")

    # Perform the scan
    results = scanner.scan()
    
    # Structure the response matches
    open_ports_list = []
    for r in results:
        # Resolve any CVEs or hints associated with the port if grabbed
        cves = []
        # If banners were grabbed, cve_mapper might have run in the scanner
        # Let's inspect the keys on port result.
        # In our implementation of scanner.py:
        # the port dictionary contains keys like: 'port', 'state', 'protocol', 'service', 'banner', 'cves', 'hints'
        open_ports_list.append(PortScanResult(
            port=r.get("port"),
            state=r.get("state"),
            protocol=r.get("protocol"),
            service=r.get("service", "unknown"),
            banner=r.get("banner"),
            cves=r.get("cves", []),
            hints=r.get("hints", [])
        ))

    duration = 0.0
    if scanner.start_time and scanner.end_time:
        duration = (scanner.end_time - scanner.start_time).total_seconds()

    return ScanResponse(
        target=target,
        ip=ip,
        scan_type=protocol.upper(),
        start_port=start_port,
        end_port=end_port,
        duration_seconds=round(duration, 2),
        os_detected=scanner.os_info,
        open_ports=open_ports_list
    )

@app.get("/api/ssl-audit")
def run_ssl_audit(
    host: str = Query(..., description="Target hostname to audit"),
    port: int = Query(443, ge=1, le=65535, description="Port running SSL/TLS (default 443)"),
    timeout: float = Query(3.0, ge=0.5, le=10.0, description="Connection timeout in seconds")
):
    """
    Audits a target server's SSL/TLS configuration: checks certificate validity,
    algorithms, serial, and tests for deprecated protocols (SSLv3, TLS 1.0, TLS 1.1).
    """
    try:
        audit_result = audit_ssl_tls(host, port, timeout)
        return audit_result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL Audit failed: {str(e)}")

@app.get("/api/dir-buster")
def run_directory_buster(
    host: str = Query(..., description="Target host (IP or domain) to scan"),
    port: int = Query(80, ge=1, le=65535, description="Web service port"),
    protocol: str = Query("http", description="Web protocol: 'http' or 'https'"),
    max_threads: int = Query(20, ge=1, le=100, description="Number of concurrent web request workers"),
    timeout: float = Query(1.0, ge=0.2, le=5.0, description="Request timeout in seconds")
):
    """
    Probes standard exposed endpoints (e.g. /.git, /.env, /admin) on a web service
    to check for configuration leaks or exposed backups.
    """
    try:
        discovered_paths = bust_directory(
            host=host,
            port=port,
            protocol=protocol.lower(),
            max_threads=max_threads,
            timeout=timeout
        )
        return {
            "target": f"{protocol}://{host}:{port}",
            "paths_checked": 34, # size of dictionary
            "discovered_count": len(discovered_paths),
            "findings": discovered_paths
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Directory buster execution failed: {str(e)}")

@app.get("/api/report/pdf")
def get_pdf_report(
    target: str = Query(..., description="Target to scan and report on"),
    start_port: int = Query(1, ge=1, le=65535),
    end_port: int = Query(1024, ge=1, le=65535),
    protocol: str = Query("tcp")
):
    """
    Runs a full scan and returns the generated PDF report as a direct file download.
    """
    try:
        scanner = NetworkScanner(
            target=target,
            start_port=start_port,
            end_port=end_port,
            timeout=1.0,
            max_threads=100,
            scan_type=protocol.lower(),
            grab_banners=True,
            include_hints=True,
            use_async=True
        )
        ip = scanner.resolve_target()
        if not ip:
            raise HTTPException(status_code=404, detail=f"Could not resolve host: {target}")
            
        results = scanner.scan()
        
        # Save report to a temporary file
        temp_dir = tempfile.gettempdir()
        pdf_path = os.path.join(temp_dir, f"scan_report_{target.replace('.', '_')}.pdf")
        
        generate_report(scanner, output_path=pdf_path)
        
        return FileResponse(
            path=pdf_path,
            filename=f"scan_report_{target}.pdf",
            media_type="application/pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")
