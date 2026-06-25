"""
Scan Scheduler - Background scanner daemon for network audits.
"""

import time
import json
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from scanner import NetworkScanner
from audit_log import AuditLogger


class ScanScheduler:
    """Singleton Scan Scheduler running a background daemon thread."""
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ScanScheduler, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance
            
    def __init__(self, schedules_file="schedules.json"):
        if self._initialized:
            return
        self.schedules_file = Path(schedules_file)
        self.audit_logger = AuditLogger()
        self.thread = None
        self.running = False
        self.lock = threading.Lock()
        self.activity_log = []
        self._initialized = True
        
    def log_activity(self, message):
        """Append scheduler activity log message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.activity_log.append(f"[{timestamp}] {message}")
        # Keep last 100 messages
        if len(self.activity_log) > 100:
            self.activity_log.pop(0)
            
    def load_schedules(self):
        """Load schedules list from JSON file."""
        with self.lock:
            if not self.schedules_file.exists():
                return []
            try:
                with open(self.schedules_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                self.log_activity(f"Error loading schedules: {e}")
                return []
                
    def save_schedules(self, schedules):
        """Save schedules list to JSON file."""
        with self.lock:
            try:
                with open(self.schedules_file, "w") as f:
                    json.dump(schedules, f, indent=4)
                return True
            except Exception as e:
                self.log_activity(f"Error saving schedules: {e}")
                return False
                
    def add_schedule(self, target, profile, protocol, interval_mins):
        """Add a new scheduled scan task."""
        schedules = self.load_schedules()
        now = datetime.now()
        new_item = {
            "id": str(uuid.uuid4()),
            "target": target,
            "profile": profile,
            "protocol": protocol,
            "interval_mins": int(interval_mins),
            "last_run": "Never",
            "next_run": now.isoformat(),
            "active": True
        }
        schedules.append(new_item)
        self.save_schedules(schedules)
        self.log_activity(f"Added schedule for {target} ({profile}/{protocol}) every {interval_mins} mins")
        return new_item
        
    def delete_schedule(self, schedule_id):
        """Delete a scheduled scan task by ID."""
        schedules = self.load_schedules()
        item = next((s for s in schedules if s["id"] == schedule_id), None)
        if item:
            schedules = [s for s in schedules if s["id"] != schedule_id]
            self.save_schedules(schedules)
            self.log_activity(f"Deleted schedule for {item['target']}")
            return True
        return False
        
    def toggle_schedule(self, schedule_id):
        """Enable or disable a scheduled task."""
        schedules = self.load_schedules()
        for s in schedules:
            if s["id"] == schedule_id:
                s["active"] = not s.get("active", True)
                self.save_schedules(schedules)
                self.log_activity(f"Toggled schedule for {s['target']} to {'Active' if s['active'] else 'Inactive'}")
                return True
        return False
        
    def start(self):
        """Start the background scheduler thread if not running."""
        with self.lock:
            if self.running:
                return
            self.running = True
            self.thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self.thread.start()
            self.log_activity("Background Scan Scheduler started.")
              
    def stop(self):
        """Stop the background scheduler thread."""
        with self.lock:
            self.running = False
            self.log_activity("Background Scan Scheduler stopped.")
              
    def _scheduler_loop(self):
        """Continuous polling loop checks if schedules are due."""
        while self.running:
            schedules = self.load_schedules()
            now = datetime.now()
            updated = False
            
            for s in schedules:
                if not s.get("active", True):
                    continue
                    
                next_run_str = s.get("next_run")
                try:
                    next_run = datetime.fromisoformat(next_run_str)
                except Exception:
                    next_run = now
                    
                if next_run <= now:
                    # Update run times
                    s["last_run"] = now.isoformat()
                    s["next_run"] = (now + timedelta(minutes=s["interval_mins"])).isoformat()
                    updated = True
                    
                    self.log_activity(f"Triggering scheduled scan on {s['target']}...")
                    # Execute scan asynchronously in another thread
                    threading.Thread(
                        target=self._execute_scan,
                        args=(s["target"], s["profile"], s["protocol"]),
                        daemon=True
                    ).start()
                    
            if updated:
                self.save_schedules(schedules)
                
            time.sleep(10)  # Check schedules every 10 seconds
              
    def _execute_scan(self, target, profile, protocol):
        """Task executor running NetworkScanner."""
        profile_map = {
            "Common (1-1024)": (None, 1, 1024),
            "Quick (Top 20)": ([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080], None, None),
            "Web (80, 443, 8080)": ([80, 443, 8080, 8443], None, None),
            "Full (1-65535)": (None, 1, 65535),
            "Custom": (None, 1, 1024)
        }
        selected_profile = profile_map.get(profile, (None, 1, 1024))
        specific_ports = selected_profile[0]
        start_port = selected_profile[1] if selected_profile[1] else 1
        end_port = selected_profile[2] if selected_profile[2] else 1
        
        try:
            # Use high-performance async scan engine
            scanner = NetworkScanner(
                target=target,
                start_port=int(start_port),
                end_port=int(end_port),
                timeout=1.0,
                max_threads=100,
                scan_type=protocol,
                grab_banners=True,
                include_hints=True,
                ports=specific_ports,
                use_async=True
            )
            result = scanner.scan()
            if result:
                self.audit_logger.log_scan(result, notes="scheduled")
                self.log_activity(f"Completed scheduled scan on {target}. Found {result['open_ports']} open ports.")
            else:
                self.log_activity(f"Scheduled scan on {target} returned no results (resolution error).")
        except Exception as e:
            self.audit_logger.log_error(target, f"Scheduled scan failed: {e}", port_range=f"{start_port}-{end_port}")
            self.log_activity(f"Scheduled scan on {target} failed: {e}")
