"""
engines/intruder/stalk.py
Network Device Discovery Scanner engine.
Scans local network for connected devices with enhanced fingerprinting capabilities.
"""
import asyncio
import socket
import subprocess
import platform
import re
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, AsyncGenerator, Dict, Any

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


@dataclass
class NetworkDevice:
    device_name: str
    device_ip: str
    mac_address: str
    network_ip: str
    vendor: str = "Unknown"
    status: str = "Offline"
    os_guess: str = "Unknown"
    open_ports: List[int] = field(default_factory=list)
    rtt_ms: Optional[float] = None
    ttl: Optional[int] = None
    device_type: str = "General"  # Mobile, Server, PC, IoT, Networking
    services: Dict[int, str] = field(default_factory=dict)
    risk_score: int = 0

    def to_dict(self):
        return asdict(self)

    @property
    def summary(self) -> str:
        rtt_str = f"RTT: {self.rtt_ms:.1f}ms" if self.rtt_ms else "RTT: N/A"
        ports_str = f"Ports: {','.join(map(str, self.open_ports))}" if self.open_ports else "No open ports"
        return f"[+] {self.device_ip:<15} | {self.mac_address} | {self.vendor:<20} | {self.os_guess} | {rtt_str} | {ports_str}"


class StalkEngine(BaseEngine):
    VERSION = "2.0.0"
    TOOL_ID = "stalk"
    CATEGORY = "intruder"

    COMMON_PORTS = [21, 22, 23, 80, 443, 445, 3389, 8080, 8443]

    def __init__(self, bus=None):
        super().__init__(bus)
        self.gateway = None
        self.network_range = None
        self.local_ip = None
        self.devices: List[NetworkDevice] = []

    async def initialize(self) -> None:
        self._get_network_info()
        self._ready = True
        self._log(f"StalkEngine v{self.VERSION} initialized. Local IP: {self.local_ip}, Gateway: {self.gateway}")

    def _get_network_info(self):
        """Get local IP and gateway based on OS (Sync helper)"""
        system = platform.system()
        try:
            if system == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                gateway_match = re.search(r'Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)', result.stdout)
                ip_match = re.search(r'IPv4 Address[^\d]*(\d+\.\d+\.\d+\.\d+)', result.stdout)
                self.local_ip = ip_match.group(1) if ip_match else None
                self.gateway = gateway_match.group(1) if gateway_match else None
            else:
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                gateway_match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.connect(("8.8.8.8", 80))
                    self.local_ip = sock.getsockname()[0]
                finally:
                    sock.close()
                self.gateway = gateway_match.group(1) if gateway_match else None

            if self.gateway:
                parts = self.gateway.split('.')
                self.network_range = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception as e:
            self._log(f"Error getting network info: {e}", level="ERROR")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        confirm = req.params.get("confirm_auth", False)
        if not confirm:
            return await self._on_error(Exception("Authorization not confirmed. Set 'confirm_auth' to True."), req)

        self.devices = []
        try:
            # Re-check network info in case of changes
            await asyncio.to_thread(self._get_network_info)
            
            if not self.gateway:
                return await self._on_error(Exception("Could not determine network gateway"), req)

            base_ip = '.'.join(self.gateway.split('.')[:3])
            ip_range = [f"{base_ip}.{i}" for i in range(1, 255)]
            
            # Concurrent scanning using asyncio chunks
            chunk_size = 50
            results = []
            for i in range(0, len(ip_range), chunk_size):
                chunk = ip_range[i:i + chunk_size]
                tasks = [self._scan_host_async(ip) for ip in chunk]
                chunk_results = await asyncio.gather(*tasks)
                results.extend(chunk_results)
            
            found_devices = [d for d in results if d]
            self.devices = found_devices

            return await self._after(Response(
                request_id=req.id,
                success=True,
                data={"devices": [d.to_dict() for d in found_devices], "count": len(found_devices)},
                elapsed_ms=(time.time() - t0) * 1000
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        scan_start_time = time.time()
        confirm = req.params.get("confirm_auth", False)
        if not confirm:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="Authorization not confirmed.")
            return

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"Starting advanced scan sequence on {self.network_range}...")
        
        await asyncio.to_thread(self._get_network_info)
        if not self.gateway:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="Gateway not found.")
            return

        base_ip = '.'.join(self.gateway.split('.')[:3])
        ip_range = [f"{base_ip}.{i}" for i in range(1, 255)]
        
        count = 0
        chunk_size = 30 # Process in batches for better UI feedback flow
        
        for i in range(0, len(ip_range), chunk_size):
            chunk = ip_range[i:i+chunk_size]
            tasks = [self._scan_host_async(ip) for ip in chunk]
            results = await asyncio.gather(*tasks)
            
            for device in results:
                if device:
                    count += 1
                    yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=device.to_dict())
                    self._emit("stalk.device_found", device.to_dict())

        elapsed = time.time() - scan_start_time
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data=f"Scan finished in {elapsed:.1f}s. Discovered {count} active host(s).")

    async def _scan_host_async(self, ip: str) -> Optional[NetworkDevice]:
        """Scan individual host asynchronously, perform advanced fingerprinting"""
        ping_result = await asyncio.to_thread(self._ping_host_ttl, ip)
        
        if ip == self.local_ip:
            mac = await asyncio.to_thread(self._get_mac_address, ip)
            hostname = await asyncio.to_thread(self._get_hostname, ip)
            vendor = self._lookup_vendor(mac)
            return NetworkDevice(
                device_name=f"{hostname} (This Machine)",
                device_ip=ip,
                mac_address=mac,
                network_ip=self.gateway or "Unknown",
                vendor=vendor,
                status="Online",
                os_guess=platform.system(),
                open_ports=[],
                device_type="Workstation",
                rtt_ms=0.0
            )

        if not ping_result['is_alive']:
            return None
            
        mac = await asyncio.to_thread(self._get_mac_address, ip)
        hostname = await asyncio.to_thread(self._get_hostname, ip)
        vendor = self._lookup_vendor(mac)
        
        device_name = hostname if hostname != "Unknown" else vendor
        if ip == self.gateway:
            device_name = f"{device_name} (Network Gateway)"

        # Heuristic OS Fingerprinting
        os_guess = "Unknown"
        if ping_result['ttl']:
            os_guess = self._guess_os_from_ttl(ping_result['ttl'])

        # Port Profiling & Service Discovery
        open_ports = []
        services = {}
        port_tasks = [self._check_port_service(ip, port) for port in self.COMMON_PORTS]
        port_results = await asyncio.gather(*port_tasks)
        
        risk_score = 0
        for port, res in zip(self.COMMON_PORTS, port_results):
            if res:
                open_ports.append(port)
                if res is not True:
                    services[port] = res
                
                # Simple risk scoring
                risk_score += 1
                if port in [22, 23, 3389]: risk_score += 3
                if port in [445, 139]: risk_score += 2

        device_type = self._detect_device_type(vendor, open_ports, os_guess)

        return NetworkDevice(
            device_name=device_name,
            device_ip=ip,
            mac_address=mac,
            network_ip=self.gateway or "Unknown",
            vendor=vendor,
            status="Online",
            os_guess=os_guess,
            open_ports=open_ports,
            rtt_ms=ping_result.get('time_ms'),
            ttl=ping_result.get('ttl'),
            device_type=device_type,
            services=services,
            risk_score=risk_score
        )

    def _ping_host_ttl(self, ip: str) -> dict:
        """Pings host and extracts TTL and Latency"""
        system = platform.system()
        param = '-n' if system == 'Windows' else '-c'
        timeout_param = '-w' if system == 'Windows' else '-W'
        try:
            result = subprocess.run(
                ['ping', param, '1', timeout_param, '800', ip],
                capture_output=True,
                text=True,
                timeout=1.5
            )
            
            is_alive = result.returncode == 0
            ttl = None
            time_ms = None
            
            if is_alive:
                ttl_match = re.search(r'TTL=(\d+)', result.stdout, re.IGNORECASE) or re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
                if ttl_match: ttl = int(ttl_match.group(1))
                
                time_match = re.search(r'time[=<](\d+\.?\d*)ms', result.stdout, re.IGNORECASE) or re.search(r'time=(\d+\.?\d*) ms', result.stdout, re.IGNORECASE)
                if time_match: time_ms = float(time_match.group(1))
                    
            return {'is_alive': is_alive, 'ttl': ttl, 'time_ms': time_ms}
        except:
            return {'is_alive': False, 'ttl': None, 'time_ms': None}

    def _guess_os_from_ttl(self, ttl: int) -> str:
        """
        Heuristic evaluation of operating system based on IP packet TTL.
        Requires interpreting standard initial TTL drops.
        """
        if ttl <= 64:
            return "Linux/Unix/macOS"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Network Device (Cisco/Solaris)"
        return "Unknown"

    async def _check_port_service(self, ip: str, port: int) -> Any:
        """Checks port and attempts basic banner grab if open"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=0.25
            )
            
            banner = True # Default if open but no banner
            try:
                if port == 80:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                elif port == 21: # FTP
                    pass # Banner usually comes first
                elif port == 22: # SSH
                    pass # Banner usually comes first
                    
                data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                if data:
                    decoded = data.decode('utf-8', 'ignore').strip()
                    if port == 80 and "Server:" in decoded:
                        for line in decoded.splitlines():
                            if line.lower().startswith("server:"):
                                banner = line.split(":", 1)[1].strip()
                                break
                    elif port == 22 and decoded.startswith("SSH-"):
                        banner = decoded.splitlines()[0]
                    elif port == 21 and decoded.startswith("220 "):
                        banner = decoded.splitlines()[0]
                    else:
                        banner = decoded[:60]
            except:
                pass
                
            writer.close()
            await writer.wait_closed()
            return banner
        except:
            return False

    def _detect_device_type(self, vendor: str, ports: List[int], os: str) -> str:
        v = vendor.lower()
        if "apple" in v or "samsung" in v or "xiaomi" in v: return "Mobile/Tablet"
        if "raspberry" in v or "arduino" in v or "esp32" in v: return "IoT/SBC"
        if "cisco" in v or "juniper" in v or "tp-link" in v or "netgear" in v: return "Networking"
        if "vmware" in v or "qemu" in v or "hyper-v" in v: return "Virtual Machine"
        
        # Port-based heuristics
        if 53 in ports or 67 in ports or 445 in ports:
            if 80 in ports or 443 in ports: return "Server/Infrastructure"
        if 3389 in ports or (80 in ports and "windows" in os.lower()): return "Workstation (Windows)"
        
        return "General Host"

    def _get_mac_address(self, ip: str) -> str:
        if ip == self.local_ip:
            import uuid
            mac_num = hex(uuid.getnode()).replace('0x', '').zfill(12)
            return '-'.join(mac_num[i:i+2] for i in range(0, 12, 2)).upper()
            
        system = platform.system()
        try:
            if system == "Windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', result.stdout)
            else:
                result = subprocess.run(['ip', 'neigh', 'show', ip], capture_output=True, text=True)
                if not result.stdout:
                    result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                mac_match = re.search(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', result.stdout)
            
            if mac_match:
                return mac_match.group(0).replace(':', '-').upper()
            return "Unknown"
        except:
            return "Unknown"

    def _get_hostname(self, ip: str) -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return "Unknown"

    def _lookup_vendor(self, mac: str) -> str:
        if not mac or mac == "Unknown":
            return "Unknown Vendor"
            
        oui = mac.replace(':', '-').upper()[:8]
        # Greatly expanded OUI lookup for enterprise asset discovery
        vendors = {
            # Virtualization & Cloud
            "00-50-56": "VMware", "08-00-27": "Oracle VirtualBox", "52-54-00": "QEMU/KVM", "00-15-5D": "Microsoft Hyper-V",
            "0A-1F-E8": "Docker", "02-42-0A": "Docker", "02-42-01": "Docker", "00-03-FF": "Microsoft Virtual",
            # Enterprise Networking
            "00-00-0C": "Cisco", "00-01-42": "Cisco", "00-01-43": "Cisco", "CC-46-D6": "Cisco", "00-60-19": "Cisco",
            "00-1B-21": "Intel", "00-0E-0C": "Intel", "00-15-17": "Intel",
            "00-0D-B4": "Juniper", "4C-96-14": "Juniper", "00-10-DB": "Juniper",
            "00-1F-12": "Fortinet", "08-5B-0E": "Fortinet", "00-09-0F": "Fortinet",
            "00-E0-81": "Palo Alto", "00-1B-17": "Palo Alto",
            "00-01-E3": "Siemens", "00-08-C7": "Siemens",
            # Edge / IoT / Consumer
            "DC-A6-32": "Raspberry Pi", "B8-27-EB": "Raspberry Pi", "D8-3A-DD": "Raspberry Pi",
            "00-17-88": "Philips Hue", "18-B4-30": "Nest Labs", "18-B4-30": "Nest", "64-16-66": "Amazon Tech", "F0-27-2D": "Amazon Tech",
            "A4-45-19": "Xiaomi", "00-9E-C8": "Xiaomi",
            "AC-DE-48": "Apple", "F0-18-98": "Apple", "00-23-DF": "Apple", "00-17-F2": "Apple", "00-1E-C2": "Apple",
            "FC-AA-14": "Samsung", "00-07-AB": "Samsung",
            "70-4F-57": "Sony", "00-02-D1": "Sony",
            "00-1A-11": "Google", "3C-5A-B4": "Google", "E4-F0-42": "Google",
            # Printers / Imaging
            "00-10-83": "HP", "00-11-0A": "HP", "00-00-48": "Epson", "00-80-77": "Brother", "00-00-5A": "Xerox"
        }
        return vendors.get(oui, "Unknown Vendor")

    def health_check(self) -> HealthStatus:
        return HealthStatus(
            engine_id=self.TOOL_ID,
            status="OK" if self.gateway else "DEGRADED",
            message=f"Gateway {self.gateway}" if self.gateway else "Gateway not detected"
        )
