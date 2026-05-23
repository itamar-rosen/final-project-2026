import socket
import threading
import queue
import json
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
            try:
                sender, p_type, gid, payload = self.sec.receive(client_obj.conn)
                if not sender: break

                # --- 1. Unique Username Enforcement ---
                if not client_obj.username and p_type == 1 and gid == "REG":
                    if sender in self.clients:
                        print(f"[-] Rejected duplicate username connection: {sender}")
                        # NEW: Actively send a rejection packet back to the client!
                        err_packet = self.sec.wrap("SERVER", 1, "ERR", b"TAKEN")
                        client_obj.conn.sendall(err_packet)
                        break  # Drops the connection

                    client_obj.username = sender
                    self.clients[sender] = client_obj
                    print(f"[+] Registered: {sender}")
                    continue

                raw_packet = self.sec.wrap(sender, p_type, gid, payload)

                # --- 2. Route Direct Messages & Sniff for Lifecycle Commands ---
                if p_type in (0, 2):
                    if gid in self.clients:
                        self.clients[gid].send(raw_packet)

                    # Sniff the unencrypted JSON payload to update server-side dictionaries
                    if p_type == 2:
                        try:
                            data = json.loads(payload.decode())
                            cmd_type = data.get('t')
                            room = data.get('room')

                            if cmd_type == 'LEAVE' and room in self.groups:
                                if sender in self.groups[room]:
                                    self.groups[room].remove(sender)
                                    print(f"[GROUP] {sender} voluntarily left {room}")

                            elif cmd_type == 'KICK' and room in self.groups:
                                if gid in self.groups[room]:
                                    self.groups[room].remove(gid)
                                    print(f"[GROUP] {gid} was kicked from {room}")

                            elif cmd_type == 'DISBAND' and room in self.groups:
                                del self.groups[room]
                                print(f"[GROUP] {room} was disbanded by the host.")
                        except:
                            pass

                # --- 3. Route to Group Members (Multicast Video/Chat) ---
                elif p_type == 3 or (p_type == 0 and gid in self.groups):
                    for member in self.groups.get(gid, []):
                        if member != sender and member in self.clients:
                            self.clients[member].send(raw_packet)

                # --- 4. Handle Dedicated Registration/Group Commands ---
                elif p_type == 1:
                    try:
                        cmd = json.loads(payload.decode()).get('a')
                        if gid == "REG" and cmd == 'QUIT':
                            break  # Exits the loop, triggering the cleanup block below

                        elif cmd == 'CREATE':
                            self.groups[gid] = [sender]
                            print(f"[GROUP] {gid} Created by {sender}")

                        elif cmd == 'JOIN':
                            if gid not in self.groups: self.groups[gid] = []
                            if sender not in self.groups[gid]:
                                self.groups[gid].append(sender)
                                print(f"[GROUP] {sender} Joined {gid}")
                    except:
                        pass

            except Exception as e:
                print(f"Relay Processing Error: {e}")
                break

        # --- 5. Global Garbage Collection (When the app closes or crashes) ---
        client_obj.active = False
        if client_obj.username:
            print(f"[-] Disconnected and Cleaned Up: {client_obj.username}")

            # Free up the username
            if client_obj.username in self.clients:
                del self.clients[client_obj.username]

            # Remove them from any rooms they were watching
            for room, members in list(self.groups.items()):
                if client_obj.username in members:
                    members.remove(client_obj.username)

            # Disband their hosted group if they were sharing their screen
            hosted_room = f"Room_{client_obj.username}"
            if hosted_room in self.groups:
                del self.groups[hosted_room]
                print(f"[GROUP] {hosted_room} Auto-Disbanded (Host disconnected)")

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow immediate port reuse to prevent "Address already in use" errors on restart
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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