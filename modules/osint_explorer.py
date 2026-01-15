import os
import shodan
import socket
from typing import Dict, Any, List

class OSINTExplorer:
    """
    OSINT Explorer that queries Shodan/Censys to find service-level exposures.
    """
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self.api = None
        if self.api_key:
            try:
                self.api = shodan.Shodan(self.api_key)
            except Exception as e:
                print(f"[!] Shodan initialization failed: {e}")

    def scan_domain(self, domain: str) -> Dict[str, Any]:
        """
        Resolves domain to IP and queries Shodan for open ports and banners.
        """
        if not self.api:
            return {"enabled": False, "message": "Shodan API key missing"}

        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            host = self.api.host(ip)
            
            ports = host.get('ports', [])
            vulns = host.get('vulns', [])
            data = host.get('data', [])
            
            exposures = []
            for item in data:
                port = item.get('port')
                product = item.get('product', 'Unknown')
                banner = item.get('data', '')
                
                # Flag high-risk ports
                if port in [3306, 5432, 27017, 6379, 21, 22, 23, 445, 3389]:
                    exposures.append({
                        "port": port,
                        "service": product,
                        "banner_snippet": banner[:100].replace('\n', ' '),
                        "severity": "HIGH"
                    })

            return {
                "enabled": True,
                "ip": ip,
                "ports": ports,
                "vulns": vulns,
                "exposures": exposures,
                "org": host.get('org', 'Unknown'),
                "os": host.get('os', 'Unknown')
            }

        except Exception as e:
            return {"enabled": True, "error": str(e)}

    def mock_scan(self, domain: str) -> Dict[str, Any]:
        """
        Returns info indicating Shodan is disabled.
        """
        return {
            "enabled": False,
            "message": "Shodan integration is currently disabled (no API key).",
            "domain": domain
        }
