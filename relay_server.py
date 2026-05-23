import socket
import threading
import queue
from pyngrok import ngrok
from protocol import SecurityEngine


class OutboundClient:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.username = None
        # Maxsize 5 guarantees the queue drops old frames if internet buffers
        self.out_queue = queue.Queue(maxsize=5)
        self.active = True

        # Start a dedicated non-blocking thread for sending data to this user
        self.worker = threading.Thread(target=self._send_loop, daemon=True)
        self.worker.start()

    def send(self, data):
        if not self.active: return
        try:
            self.out_queue.put_nowait(data)
        except queue.Full:
            # Smart Frame Dropping: Toss the oldest frame to make room for real-time
            try:
                self.out_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self.out_queue.put_nowait(data)
            except queue.Full:
                pass

    def _send_loop(self):
        while self.active:
            try:
                data = self.out_queue.get(timeout=1.0)
                self.conn.sendall(data)
            except queue.Empty:
                pass
            except Exception:
                self.active = False
                break
        self.conn.close()


class RelayServer:
    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 8000
        self.sec = SecurityEngine()
        self.clients = {}  # {username: OutboundClient}
        self.groups = {}  # {gid: [username1, username2...]}

    def handle_client(self, client_obj):
        while client_obj.active:
            sender, p_type, gid, payload = self.sec.receive(client_obj.conn)
            if not sender: break

            if not client_obj.username and p_type == 1 and gid == "REG":
                client_obj.username = sender
                self.clients[sender] = client_obj
                print(f"[+] Registered: {sender}")
                continue

            raw_packet = self.sec.wrap(sender, p_type, gid, payload)

            # Route to a specific user (1-on-1 commands)
            if p_type in (0, 2):
                if gid in self.clients:
                    self.clients[gid].send(raw_packet)

            # Route to group members (1-to-Many Multicast Video/Chat)
            elif p_type == 3 or (p_type == 0 and gid in self.groups):
                for member in self.groups.get(gid, []):
                    if member != sender and member in self.clients:
                        self.clients[member].send(raw_packet)

            # Group management requests
            elif p_type == 1:
                cmd = __import__('json').loads(payload.decode()).get('a')
                if cmd == 'CREATE':
                    self.groups[gid] = [sender]
                    print(f"[GROUP] {gid} Created by {sender}")
                elif cmd == 'JOIN':
                    if gid not in self.groups: self.groups[gid] = []
                    if sender not in self.groups[gid]:
                        self.groups[gid].append(sender)
                        print(f"[GROUP] {sender} Joined {gid}")

        client_obj.active = False
        if client_obj.username in self.clients:
            del self.clients[client_obj.username]

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(50)

        tunnel = ngrok.connect(self.port, 'tcp')
        print(f"[*] Relay started! Join URL: {tunnel.public_url}")

        while True:
            conn, addr = server.accept()
            c_obj = OutboundClient(conn, addr)
            threading.Thread(target=self.handle_client, args=(c_obj,), daemon=True).start()


if __name__ == "__main__":
    RelayServer().start()