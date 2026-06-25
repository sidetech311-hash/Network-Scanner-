"""
Audit logging and scan history export for the Network Scanner.
"""

import csv
import json
from datetime import datetime
from pathlib import Path


class AuditLogger:
    """Log scans to CSV and JSON for compliance and history tracking."""
    
    def __init__(self, log_file="scan_history.csv"):
        self.log_file = Path(log_file)
        self._ensure_csv_header()
    
    def _ensure_csv_header(self):
        """Create CSV file with header if it doesn't exist."""
        if not self.log_file.exists():
            with open(self.log_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "target",
                    "ip",
                    "scan_type",
                    "port_range",
                    "open_ports_count",
                    "duration",
                    "os_detected",
                    "status",
                    "notes"
                ])
    
    def log_scan(self, scan_result, status="success", notes=""):
        """
        Log a completed scan to the audit CSV.
        
        Args:
            scan_result: dict from scanner.scan()
            status: 'success', 'partial', or 'failed'
            notes: optional string for additional context
        """
        timestamp = datetime.now().isoformat()
        port_range = f"{scan_result.get('start_port', '?')}-{scan_result.get('end_port', '?')}"
        
        with open(self.log_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                scan_result.get("target", "unknown"),
                scan_result.get("ip", "unknown"),
                scan_result.get("scan_type", "tcp"),
                port_range,
                scan_result.get("open_ports", 0),
                scan_result.get("duration", "0:00:00"),
                scan_result.get("os", "Unknown"),
                status,
                notes
            ])
    
    def log_error(self, target, error_msg, port_range="unknown"):
        """Log a failed scan attempt."""
        timestamp = datetime.now().isoformat()
        with open(self.log_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                target,
                "error",
                "N/A",
                port_range,
                0,
                "N/A",
                "N/A",
                "failed",
                error_msg[:200]  # Truncate long error messages
            ])
    
    def get_history(self, limit=50):
        """
        Retrieve scan history as list of dicts.
        
        Args:
            limit: max number of recent scans to return
        
        Returns:
            list of scan records
        """
        if not self.log_file.exists():
            return []
        
        records = []
        with open(self.log_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(row)
        
        return records[-limit:]  # Return most recent
    
    def export_json(self, output_file="scan_history.json"):
        """Export audit log as JSON."""
        history = self.get_history(limit=1000)
        with open(output_file, "w") as f:
            json.dump(history, f, indent=2)
        return output_file
    
    def get_stats(self):
        """Get summary statistics from audit log."""
        history = self.get_history(limit=1000)
        if not history:
            return {}
        
        total_scans = len(history)
        successful = sum(1 for r in history if r.get("status") == "success")
        failed = sum(1 for r in history if r.get("status") == "failed")
        
        return {
            "total_scans": total_scans,
            "successful": successful,
            "failed": failed,
            "success_rate": round(100 * successful / total_scans, 1) if total_scans > 0 else 0,
        }
