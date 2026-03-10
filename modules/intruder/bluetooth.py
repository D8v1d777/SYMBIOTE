import threading

class BluetoothEngine(threading.Thread):
    """Persistent Bluetooth Device Scanner using PyBluez with friendly-name resolution."""

    def __init__(self, callback=None, interval=5, max_cycles=0, colors=None):
        super().__init__(daemon=True)
        self.callback   = callback
        self.interval   = interval
        self.max_cycles = max_cycles
        self._stop_flag = threading.Event()
        self.seen       = {}
        self.colors = colors or {
            "accent_cyan": "#00FFFF",
            "accent_gold": "#FFD700"
        }

    def _log(self, msg, color=None):
        if self.callback:
            self.callback(msg, color or self.colors.get("accent_cyan"))

    def stop(self):
        self._stop_flag.set()

    def run(self):
        self._log("[BT] Scanner is currently disabled due to system-level instability.", self.colors.get("accent_gold"))

    def _scan_once(self):
        pass

    @staticmethod
    def lookup_name(mac: str) -> str:
        try:
            import bluetooth
            name = bluetooth.lookup_name(mac, timeout=5)
            return name or "<unknown>"
        except Exception:
            return "<lookup failed>"
