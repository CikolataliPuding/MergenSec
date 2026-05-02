"""
AsyncScanner — Asynchronous Network Port and Service Discovery

SPRINT 2 (Days 5-6): Implement AsyncScanner with python-nmap and asyncio
SPRINT 3 (Days 11-17): Integration with dashboard

Responsibilities:
- Perform async port scanning using nmap
- Detect open ports and service banners
- Return structured service discovery data
"""

import asyncio
import logging
from typing import Any, Optional

try:
    import nmap
except ImportError:
    raise ImportError("python-nmap is required. Install with: pip install python-nmap")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AsyncScanner:
    """
    Asynchronous network scanner using python-nmap.
    
    Scans target IP addresses or CIDR ranges for open ports and running services.
    
    Attributes:
        target: Target IP address or CIDR range
        nm: Nmap PortScanner instance
        results: Scan results dictionary
    """
    
    def __init__(self, target: str):
        """
        Initialize scanner with target.
        
        Args:
            target: IP address (e.g., "192.168.1.1") or CIDR range (e.g., "192.168.1.0/24")
            
        Raises:
            ValueError: If target format is invalid
        """
        if not target or not isinstance(target, str):
            raise ValueError("Target must be a non-empty string")
        
        self.target = target.strip()
        self.nm = nmap.PortScanner()
        self.results = {}
        logger.info(f"AsyncScanner initialized for target: {self.target}")
    
    async def scan(
        self,
        ports: str = "1-65535",
        arguments: str = "-sV -O",
        sudo: bool = False
    ) -> dict[str, Any]:
        """
        Execute async network scan.
        
        Args:
            ports: Port range (default: "1-65535" for all)
            arguments: Nmap arguments (default: "-sV -O" for service and OS detection)
            sudo: Whether to use sudo/run as administrator
            
        Returns:
            dict: Scan results with discovered ports and services
            
        Example:
            {
                "host": "192.168.1.1",
                "scan_time": "2025-01-01T12:00:00",
                "status": "success",
                "ports": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "product": "Apache httpd",
                        "version": "2.4.51"
                    }
                ]
            }
        """
        try:
            logger.info(f"Starting scan of {self.target} on ports {ports}")
            
            # Perform async scan (blocking operation in thread pool)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self._perform_nmap_scan,
                ports,
                arguments,
                sudo
            )
            
            # Parse and return results
            self.results = self._parse_scan_results()
            logger.info(f"Scan completed. Found {len(self.results.get('ports', []))} open ports")
            
            return self.results
            
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            raise RuntimeError(f"Network scan failed: {str(e)}")
    
    def _perform_nmap_scan(self, ports: str, arguments: str, sudo: bool):
        """Execute actual nmap scan (blocking operation)."""
        sudo_prefix = "-sudo " if sudo else ""
        args = f"{sudo_prefix}{arguments}"
        self.nm.scan(hosts=self.target, ports=ports, arguments=args)
    
    def _parse_scan_results(self) -> dict[str, Any]:
        """Parse nmap results into structured format."""
        ports_data = []
        
        # Get all hosts from scan
        for host in self.nm.all_hosts():
            if self.nm[host].state() == "up":
                
                # Get all ports from this host
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        
                        # Only include open ports
                        if port_info['state'] == 'open':
                            ports_data.append({
                                "port": int(port),
                                "protocol": proto,
                                "state": port_info['state'],
                                "service": port_info.get('name', 'unknown'),
                                "product": port_info.get('product', 'N/A'),
                                "version": port_info.get('version', 'N/A'),
                                "extrainfo": port_info.get('extrainfo', '')
                            })
        
        # Sort by port number
        ports_data.sort(key=lambda x: x['port'])
        
        # Format timestamp
        scan_time = self.nm.scanstats().get('timestr', '')
        
        return {
            "host": self.target,
            "scan_time": scan_time,
            "status": "success",
            "ports": ports_data
        }
    
    def get_open_ports(self) -> list[dict[str, Any]]:
        """
        Get list of open ports from last scan.
        
        Returns:
            list: List of open port information dictionaries
        """
        return self.results.get('ports', [])
    
    def get_services(self) -> list[dict[str, Any]]:
        """
        Get list of detected services from last scan.
        
        Returns:
            list: List of service information dictionaries
        """
        services = []
        for port_info in self.get_open_ports():
            service = {
                "port": port_info['port'],
                "protocol": port_info['protocol'],
                "name": port_info['service'],
                "product": port_info['product'],
                "version": port_info['version']
            }
            services.append(service)
        
        return services
    
    def get_service_string(self, port: int) -> str:
        """
        Get service search string for given port.
        
        Args:
            port: Port number
            
        Returns:
            str: Service string for CVE lookup (e.g., "Apache httpd 2.4.51")
        """
        for port_info in self.get_open_ports():
            if port_info['port'] == port:
                product = port_info.get('product', '').strip()
                version = port_info.get('version', '').strip()
                
                if product and version:
                    return f"{product} {version}"
                elif product:
                    return product
                else:
                    return port_info.get('service', 'unknown')
        
        return "unknown"


async def scan_target(target: str, verbose: bool = False) -> dict[str, Any]:
    """
    Convenience function for scanning a target.
    
    Args:
        target: IP address or CIDR range
        verbose: Enable verbose logging
        
    Returns:
        dict: Scan results
    """
    if verbose:
        logger.setLevel(logging.DEBUG)
    
    scanner = AsyncScanner(target)
    results = await scanner.scan()
    return results
