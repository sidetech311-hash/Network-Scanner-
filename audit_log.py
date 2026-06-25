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
        Log a completed scan to the audit CSV and save detailed JSON.
        
        Args:
            scan_result: dict from scanner.scan()
            status: 'success', 'partial', or 'failed'
            notes: optional string for additional context
        """
        timestamp = datetime.now().isoformat()
        port_range = f"{scan_result.get('start_port', '?')}-{scan_result.get('end_port', '?')}"
        
        # Save detailed JSON file in 'scans' directory
        scans_dir = Path("scans")
        scans_dir.mkdir(exist_ok=True)
        
        try:
            dt = datetime.fromisoformat(timestamp)
            ts_str = dt.strftime("%Y%m%d_%H%M%S")
        except Exception:
            ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            
        json_filename = f"scan_{scan_result.get('ip', 'unknown')}_{ts_str}.json"
        json_path = scans_dir / json_filename
        
        # Save detailed JSON representation
        with open(json_path, "w") as f:
            json.dump(scan_result, f, indent=4)
            
        # Store json filename in notes column for referencing/deletion
        full_notes = json_filename if not notes else f"{notes}|{json_filename}"
        
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
                full_notes
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
    
    def delete_scan(self, timestamp_to_delete):
        """Delete a scan record from CSV and remove its detailed JSON file if it exists."""
        if not self.log_file.exists():
            return False
            
        rows = []
        deleted = False
        with open(self.log_file, "r") as f:
            reader = csv.reader(f)
            header = next(reader)
            rows.append(header)
            for row in reader:
                if row[0] == timestamp_to_delete:
                    deleted = True
                    # Check if there is an associated JSON filename in notes
                    notes_col = row[9] if len(row) > 9 else ""
                    json_filename = ""
                    if "|" in notes_col:
                        parts = notes_col.split("|")
                        if len(parts) > 1 and parts[1].endswith(".json"):
                            json_filename = parts[1]
                    elif notes_col.endswith(".json"):
                        json_filename = notes_col
                        
                    if json_filename:
                        json_path = Path("scans") / json_filename
                        if json_path.exists():
                            try:
                                json_path.unlink()
                            except Exception:
                                pass
                else:
                    rows.append(row)
                    
        if deleted:
            with open(self.log_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            return True
        return False
        
    def get_detailed_scan(self, json_filename):
        """Load a detailed scan result from its JSON file."""
        json_path = Path("scans") / json_filename
        if json_path.exists():
            with open(json_path, "r") as f:
                return json.load(f)
        return None
    
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
