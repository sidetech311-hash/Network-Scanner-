"""
SSH Credentialed Auditor - Connects to host via SSH and performs security compliance audits.
"""

import io
import re
import paramiko


class SSHAuditor:
    """Connects to Linux systems via SSH to perform internal security compliance reviews."""
    
    def __init__(self, host, port=22, username="root", password=None, pkey_content=None):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.pkey_content = pkey_content  # String content of uploaded private key file
        self.client = None

    def connect(self):
        """Establish SSH connection using password or private key."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        pkey = None
        if self.pkey_content:
            # Attempt to parse as various key types
            for key_class in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]:
                try:
                    pkey = key_class.from_private_key(io.StringIO(self.pkey_content), password=self.password)
                    break
                except Exception:
                    pass
            if not pkey:
                raise ValueError("Failed to parse private key content. Verify file format and passphrase.")

        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            pkey=pkey,
            timeout=10.0
        )

    def execute_command(self, cmd):
        """Execute a remote shell command and return stdout, stderr, and exit status."""
        if not self.client:
            raise Exception("SSH connection not active.")
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=10.0)
        exit_status = stdout.channel.recv_exit_status()
        stdout_str = stdout.read().decode("utf-8", errors="ignore")
        stderr_str = stderr.read().decode("utf-8", errors="ignore")
        return stdout_str, stderr_str, exit_status

    def run_audit(self):
        """Perform system information gather, listing ports check, package audit, and warning generation."""
        try:
            self.connect()
        except Exception as e:
            return {"success": False, "error": f"SSH connection failed: {e}"}
            
        results = {
            "success": True,
            "host": self.host,
            "os_info": {},
            "listening_ports": [],
            "packages": [],
            "warnings": []
        }
        
        # 1. Gather OS Release Info
        try:
            out, _, status = self.execute_command("cat /etc/os-release")
            if status == 0:
                for line in out.splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        results["os_info"][k.strip()] = v.strip().strip('"')
        except Exception:
            pass
            
        if not results["os_info"]:
            try:
                out, _, status = self.execute_command("uname -a")
                if status == 0:
                    results["os_info"]["UNAME"] = out.strip()
            except Exception:
                pass

        # 2. Gather Internal Listening Ports
        try:
            # Try ss first (newer Linux), then fall back to netstat
            out, _, status = self.execute_command("ss -tulpn || netstat -tulpn")
            if status == 0:
                lines = out.splitlines()
                # Parse ss output format:
                # Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0]
                        # ss puts Local Address in column 5 (index 4) if State exists, netstat differs
                        local_addr = parts[4] if len(parts) > 5 and parts[1] == "LISTEN" else parts[3]
                        
                        if ":" in local_addr:
                            addr, port = local_addr.rsplit(":", 1)
                            # Extract process info
                            process = "Unknown"
                            proc_match = re.search(r'"([^"]+)"', line)
                            if proc_match:
                                process = proc_match.group(1)
                            elif "users:" in line:
                                # Example: users:(("sshd",pid=1025,fd=3))
                                p_m = re.search(r'users:\(\("([^"]+)"', line)
                                if p_m:
                                    process = p_m.group(1)
                                    
                            results["listening_ports"].append({
                                "protocol": proto.upper(),
                                "port": port,
                                "address": local_addr,
                                "process": process
                            })
        except Exception:
            pass

        # 3. Gather Installed Packages (supports dpkg for Debian/Ubuntu and rpm for RHEL/CentOS)
        try:
            dpkg_out, _, dpkg_status = self.execute_command("dpkg-query -W -f='${Package} ${Version}\\n'")
            if dpkg_status == 0:
                for line in dpkg_out.splitlines():
                    if " " in line:
                        pkg, ver = line.split(" ", 1)
                        results["packages"].append({"name": pkg, "version": ver})
            else:
                rpm_out, _, rpm_status = self.execute_command("rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n'")
                if rpm_status == 0:
                    for line in rpm_out.splitlines():
                        if " " in line:
                            pkg, ver = line.split(" ", 1)
                            results["packages"].append({"name": pkg, "version": ver})
        except Exception:
            pass

        # 4. Analyze results and generate vulnerability compliance warnings
        self._generate_warnings(results)
        
        self.disconnect()
        return results

    def disconnect(self):
        """Close client connection."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

    def _generate_warnings(self, results):
        """Verify package versions and wildcard listening exposures."""
        warnings = []
        
        # 1. Package Vulnerability Checks
        for pkg in results["packages"]:
            pkg_name = pkg["name"].lower()
            pkg_ver = pkg["version"]
            
            # Check for outdated OpenSSH server
            if "openssh-server" in pkg_name or "openssh" == pkg_name:
                match = re.search(r'^(\d+)\.(\d+)', pkg_ver)
                if match:
                    major, minor = int(match.group(1)), int(match.group(2))
                    if (major < 9) or (major == 9 and minor < 8):
                        warnings.append(
                            f"CRITICAL: Outdated OpenSSH server ({pkg_ver}). "
                            f"Vulnerable to RegreSSHion RCE (CVE-2024-6387). "
                            f"Update SSH daemon immediately."
                        )
                        
            # Check for legacy Bash (Shellshock vulnerability)
            elif "bash" == pkg_name:
                match = re.search(r'^(\d+)\.(\d+)', pkg_ver)
                if match:
                    major = int(match.group(1))
                    if major < 4:
                        warnings.append(
                            f"HIGH: Legacy Bash shell version ({pkg_ver}) detected. "
                            f"Vulnerable to Shellshock (CVE-2014-6271). Update bash package."
                        )
                        
            # Check for older OpenSSL branches
            elif "openssl" == pkg_name:
                if pkg_ver.startswith("1.0.1") or pkg_ver.startswith("1.0.2") or pkg_ver.startswith("1.1.0"):
                    warnings.append(
                        f"HIGH: Outdated OpenSSL library version ({pkg_ver}). "
                        f"End-of-life library branch with multiple known CVE vulnerabilities. Update to OpenSSL 3.0+."
                    )

        # 2. Wildcard Port Binding Checks (Exposed databases/admin portals)
        for p in results["listening_ports"]:
            port = p["port"]
            addr = p["address"]
            proc = p["process"]
            
            # Check if common sensitive services listen on all interfaces (0.0.0.0 or [::] or *)
            is_wildcard = any(w in addr for w in ["0.0.0.0", "[::]", "*"])
            if is_wildcard and port in ["3306", "5432", "6379", "27017", "9200"]:
                service_name = "MySQL" if port == "3306" else "Postgres" if port == "5432" else "Redis" if port == "6379" else "MongoDB" if port == "27017" else "Elasticsearch"
                warnings.append(
                    f"HIGH: {service_name} database ('{proc}') is listening on wildcard interface ({addr}) on port {port}. "
                    f"Should be bound to 127.0.0.1 (localhost) unless public exposure is explicitly required."
                )
                
            if is_wildcard and port == "22" and proc != "sshd":
                warnings.append(
                    f"MEDIUM: SSH daemon process is listed as '{proc}' instead of standard 'sshd' on wildcard interface."
                )

        results["warnings"] = warnings
