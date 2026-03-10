import re
import sys

def modify():
    with open('e:/VulnScanner/OmniVulnScanner.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Remove EventBus, WebSocketServer, BaseEngine
    # We find the architecture block and remove it carefully.
    start_str1 = "# ==================== ARCHITECTURE & EVENT BUS ===================="
    end_str1 = "# ==================== CYBERPUNK SYSTEM CONFIG ===================="
    
    idx1 = content.find(start_str1)
    idx2 = content.find(end_str1)
    if idx1 != -1 and idx2 != -1:
        content = content[:idx1] + content[idx2:]
        print("Removed architecture block")

    # 2. Remove ExploitEngine -> SSHBruteEngine stubs
    start_str2 = "# ==================== ADVANCED SCANNING ENGINES ===================="
    end_str2 = "class WafDetector:"
    
    idx3 = content.find(start_str2)
    idx4 = content.find(end_str2)
    if idx3 != -1 and idx4 != -1:
        content = content[:idx3 + len(start_str2) + 1] + content[idx4:]
        print("Removed advanced engine stubs (Exploit to SSHBrute)")

    # 3. Remove 24-ENGINE ARCHITECTURE stubs
    start_str3 = "# ==================== NEW 24-ENGINE ARCHITECTURE ===================="
    end_str3 = "# ==================== ADVANCED CUSTOM WIDGETS ===================="
    
    idx5 = content.find(start_str3)
    idx6 = content.find(end_str3)
    if idx5 != -1 and idx6 != -1:
        content = content[:idx5] + content[idx6:]
        print("Removed 24-ENGINE ARCHITECTURE stubs")
        
    # 4. Remove ws_server and local 24-engine dictionary initializations in SYMBIOTEApp.__init__
    old_init = """        # Architecture: Event Bus & WebSocket
        self.ws_server = WebSocketServer(port=9999, bus=event_bus)
        self.ws_server.start()
        
        self.engines = {
            "template": TemplateEngine(),
            "network": NetworkScanner(),
            "web": WebScanner(),
            "waf": WafDetector(),
            "subdomain": SubdomainScanner(),
            "cors": CorsScanner(),
            "fuzzer": FuzzEngine(),
            "mapper": ExploitMapper(),
            "discovery": NetworkDiscoveryScanner(),
            "router": RouterAssessor(),
            "settings": self.settings,
            "sqli": SQLiEngine(),
            "brute": BruteForceEngine(),
            "wifi": WiFiEngine(),
            "harvester": CredentialHarvester(),
            
            # --- The 24-Engine Architecture ---
            "exploit": ExploitEngine(),
            "ropchain": ROPChainEngine(),
            "emulation": EmulationEngine(),
            "disassembly": DisassemblyEngine(),
            "ssh_brute": SSHBruteEngine(),
            "browser": BrowserEngine(),
            "serial": SerialEngine(),
            "bluetooth": BluetoothEngine(),
            "remote": RemoteEngine(),
            "packet": PacketEngine(),
            "shodan_intel": ShodanEngine(),
            "domain": DomainEngine(),
            "pcap": PacketCaptureEngine(),
            "android_recon": AndroidReconEngine(),
            "ble_recon": BLEReconEngine(),
            "web_crawl": WebCrawlEngine(),
            "osint": OsintEngine(),
            "elf_analysis": ELFAnalysisEngine(),
            "static_audit": StaticAuditEngine(),
            "dependency": DependencyEngine(),
            "android_analysis": AndroidAnalysisEngine(),
            "sys_metrics": SystemMetricsEngine(),
            "settings_db": SettingsEngine(),
            "ipython": IPythonEngine()
        }"""
        
    new_init = """        self.engines = {
            "template": TemplateEngine(),
            "network": NetworkScanner(),
            "web": WebScanner(),
            "waf": WafDetector(),
            "subdomain": SubdomainScanner(),
            "cors": CorsScanner(),
            "fuzzer": FuzzEngine(),
            "mapper": ExploitMapper(),
            "discovery": NetworkDiscoveryScanner(),
            "router": RouterAssessor(),
            "settings": self.settings,
            "sqli": SQLiEngine(),
            "brute": BruteForceEngine(),
            "wifi": WiFiEngine(),
            "harvester": CredentialHarvester(),
        }"""
        
    if old_init in content:
        content = content.replace(old_init, new_init)
        print("Replaced SYMBIOTEApp.__init__ dictionary")

    # 5. Fix up __main__ block
    old_main = """if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = SYMBIOTEApp()
    win.show()
    sys.exit(app.exec())"""

    new_main = """if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    from registry.event_bus import bus
    from registry.engine_registry import registry
    from registry.health_aggregator import HealthAggregator
    from server.ws_server import WSServer
    
    print("[BOOT] Loading engine registry...")
    registry.load_all()

    loaded = registry.list_ids()
    errors = registry.errors()
    print(f"[BOOT] Engines loaded: {len(loaded)}  |  Errors: {len(errors)}")
    if errors:
        for mod, err in errors.items():
            print(f"  [WARN] {mod}: {err}")

    print("[BOOT] Starting health aggregator...")
    aggregator = HealthAggregator(registry=registry, bus=bus, interval=5.0)
    aggregator.start()

    print("[BOOT] Starting WebSocket server on :9999...")
    ws = WSServer(port=9999)
    ws.start()

    bus.emit("app.started", {"engines": len(loaded), "errors": len(errors)}, source="main")

    app = QApplication.instance() or QApplication(sys.argv)
    win = SYMBIOTEApp()
    
    # Wire new engines into the window's existing engines dict
    for engine_id, engine in registry._engines.items():
        win.engines[engine_id] = engine
        
    win.show()
    sys.exit(app.exec())"""

    if old_main in content:
        content = content.replace(old_main, new_main)
        print("Replaced __main__ block")
        
    with open('e:/VulnScanner/OmniVulnScanner.py', 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == '__main__':
    modify()
    print("Done")
