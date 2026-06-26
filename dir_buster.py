"""
Web Directory Buster for Network Scanner.
Probes web services for exposed credentials, backups, administrative panels, and repositories.
"""

import requests
import concurrent.futures

# Critical files/directories list with risk descriptions
DIRECTORY_DICTIONARY = {
    "/.git/": "Exposed Git Repository",
    "/.git/config": "Exposed Git Repository Configuration",
    "/.env": "Exposed Environment Credentials File",
    "/.htaccess": "Exposed Apache Server Access Config",
    "/admin/": "Potential Administrator Control Panel",
    "/wp-admin/": "WordPress Admin Login Panel",
    "/wp-config.php": "WordPress Configuration File (Source Leak Check)",
    "/config.php": "Application Config Script",
    "/config.json": "Application Config Settings File",
    "/database.sql": "Exposed SQL Database Dump",
    "/backup.zip": "Exposed Backup Archive File",
    "/backup/": "Exposed Backup Directory",
    "/robots.txt": "Search Engine Directives (Robots Index)",
    "/server-status": "Apache Server Information Page",
    "/phpinfo.php": "PHP Information and Environment Leak",
    "/composer.json": "Composer PHP Package Dependency Config",
    "/package.json": "NodeJS Package Dependency Config",
    "/docker-compose.yml": "Docker Compose Deployment Config",
    "/api/": "API Base Endpoint",
    "/swagger/": "Exposed Swagger/OpenAPI API Docs",
    "/console/": "Exposed Web Console Panel",
    "/login": "Web Service Login Endpoint",
    "/dashboard": "Dashboard Control Panel",
    "/.vscode/": "Exposed VS Code Configuration Folder",
}

def check_path(url, path, description, timeout=1.0):
    """
    Checks if a single path exists under the target URL.
    Attempts HEAD first for speed, falling back to GET on 405.
    """
    full_url = f"{url.rstrip('/')}{path}"
    try:
        # Try HEAD request first for raw performance
        r = requests.head(full_url, timeout=timeout, allow_redirects=False)
        
        # If method not allowed, try GET instead
        if r.status_code == 405:
            r = requests.get(full_url, timeout=timeout, allow_redirects=False)
            
        status = r.status_code
        # We flag 200 (OK) and 403 (Forbidden - indicates directory is present but locked)
        if status in (200, 301, 302, 403):
            # Check 403 or redirects
            status_desc = "OK"
            if status == 403:
                status_desc = "Forbidden (Directory exists)"
            elif status in (301, 302):
                status_desc = f"Redirect ({r.headers.get('Location', '')})"
                
            return {
                "path": path,
                "url": full_url,
                "status": status,
                "status_desc": status_desc,
                "name": description,
            }
    except Exception:
        pass
    return None

def bust_directory(host, port=80, protocol="http", max_threads=20, timeout=1.0, progress_callback=None):
    """
    Runs concurrent probes for common exposed directories on the target host.
    """
    base_url = f"{protocol}://{host}:{port}"
    discovered = []
    
    paths = list(DIRECTORY_DICTIONARY.items())
    total = len(paths)
    checked = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(check_path, base_url, path, desc, timeout): path
            for path, desc in paths
        }
        for future in concurrent.futures.as_completed(futures):
            checked += 1
            if progress_callback:
                progress_callback(checked, total)
            try:
                res = future.result()
                if res:
                    discovered.append(res)
            except Exception:
                pass
                
    return sorted(discovered, key=lambda x: x["path"])
