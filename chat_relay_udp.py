import socket
import threading
import json
import time
import sys

# --- CONFIGURATION ---
SERVER_LOCAL_PORT = 19132
SERVER_PUBLIC_DNS = "processing-webshots.gl.at.ply.gg"
SERVER_PUBLIC_PORT = 12273


# ---------------------------------------------------------
# PROTOCOL (The Message Builder)
# ---------------------------------------------------------
class ChatProtocol:
    @staticmethod
    def parse(raw_data):
        try:
            text = raw_data.decode('utf-8', errors='ignore')
            json_start = text.find('{')
            if json_start == -1: return None
            return json.loads(text[json_start:])
        except:
            return None

    @staticmethod
    def build_register(name):
        return json.dumps({"type": "REGISTER", "name": name}).encode()

    @staticmethod
    def build_connect_request(sender, target):
        return json.dumps({"type": "CONNECT_REQUEST", "from": sender, "to": target}).encode()

    @staticmethod
    def build_connect_accept(sender, target):
        return json.dumps({"type": "CONNECT_ACCEPT", "from": sender, "to": target}).encode()

    @staticmethod
    def build_disconnect(sender, target):
        return json.dumps({"type": "DISCONNECT", "from": sender, "to": target}).encode()

    @staticmethod
    def build_chat(sender, target, text):
        return json.dumps({
            "type": "CHAT",
            "from": sender,
            "to": target,
            "length": len(text),
            "message": text,
            "timestamp": time.time()
        }).encode()

    @staticmethod
    def build_user_list(active_users):
        return json.dumps({"type": "USER_LIST", "users": active_users}).encode()

    @staticmethod
    def build_incoming_request(sender):
        return json.dumps({"type": "INCOMING_REQUEST", "from": sender}).encode()

    @staticmethod
    def build_request_accepted(sender):
        return json.dumps({"type": "REQUEST_ACCEPTED", "from": sender}).encode()


# ---------------------------------------------------------
# SERVER (The Relay Hub)
# ---------------------------------------------------------
class ChatRelayServer:
    def __init__(self):
        self.clients = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = True

    def start(self):
        print("--- RELAY SERVER STARTED ---")
        try:
            self.sock.bind(('0.0.0.0', SERVER_LOCAL_PORT))
            print(f"[*] Listening on UDP: 0.0.0.0:{SERVER_LOCAL_PORT}")
        except Exception as e:
            print(f"[!] Bind Error: {e}")
            return

        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                packet = ChatProtocol.parse(data)

                if not packet: continue
                msg_type = packet.get('type')

                # 1. HEARTBEAT / REGISTRATION
                if msg_type == 'REGISTER':
                    name = packet['name']

                    if name not in self.clients:
                        print(f"[+] '{name}' joined the lobby from {addr}")

                    self.clients[name] = {'addr': addr, 'last_seen': time.time()}

                    now = time.time()
                    self.clients = {k: v for k, v in self.clients.items() if now - v['last_seen'] < 15}

                    active_users = list(self.clients.keys())
                    active_users.remove(name)

                    reply = ChatProtocol.build_user_list(active_users)
                    self.sock.sendto(reply, addr)

                # 2. ROUTE REQUESTS, APPROVALS, AND DISCONNECTS
                elif msg_type in ['CONNECT_REQUEST', 'CONNECT_ACCEPT', 'DISCONNECT']:
                    target_name = packet['to']
                    sender_name = packet['from']

                    if target_name in self.clients:
                        target_addr = self.clients[target_name]['addr']

                        if msg_type == 'CONNECT_REQUEST':
                            out_msg = ChatProtocol.build_incoming_request(sender_name)
                        elif msg_type == 'CONNECT_ACCEPT':
                            out_msg = ChatProtocol.build_request_accepted(sender_name)
                        elif msg_type == 'DISCONNECT':
                            out_msg = ChatProtocol.build_disconnect(sender_name, target_name)

                        self.sock.sendto(out_msg, target_addr)
                        print(f"[*] Routed {msg_type}: {sender_name} -> {target_name}")

                # 3. CHAT MESSAGE ROUTING
                elif msg_type == 'CHAT':
                    target_name = packet['to']
                    if target_name in self.clients:
                        target_addr = self.clients[target_name]['addr']
                        self.sock.sendto(data, target_addr)

            except Exception as e:
                pass


# ---------------------------------------------------------
# CLIENT (The User)
# ---------------------------------------------------------
class ChatRelayClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = True
        self.name = ""
        self.approved_connections = set()
        self.online_users = []

    def _send_heartbeat(self):
        while self.running:
            if self.name:
                packet = ChatProtocol.build_register(self.name)
                try:
                    self.sock.sendto(packet, (SERVER_PUBLIC_DNS, SERVER_PUBLIC_PORT))
                except:
                    pass
            time.sleep(3)

    def _listen(self):
        last_user_list = []

        while self.running:
            try:
                data, _ = self.sock.recvfrom(4096)
                packet = ChatProtocol.parse(data)

                if not packet: continue
                msg_type = packet.get('type')

                # 1. UPDATE USER LIST
                if msg_type == 'USER_LIST':
                    users = packet['users']
                    self.online_users = users
                    if users != last_user_list:
                        sys.stdout.write(f"\r\n[Server] Online Users: {', '.join(users) if users else 'None'}\n> ")
                        sys.stdout.flush()
                        last_user_list = users

                # 2. INCOMING REQUEST
                elif msg_type == 'INCOMING_REQUEST':
                    sender = packet['from']
                    sys.stdout.write(
                        f"\r\n[!] REQUEST: '{sender}' wants to chat. \nType '/accept {sender}' to allow them.\n> ")
                    sys.stdout.flush()

                # 3. REQUEST ACCEPTED
                elif msg_type == 'REQUEST_ACCEPTED':
                    sender = packet['from']
                    self.approved_connections.add(sender)
                    sys.stdout.write(f"\r\n[!] '{sender}' accepted your request! You can now chat.\n> ")
                    sys.stdout.flush()

                # 4. DISCONNECT
                elif msg_type == 'DISCONNECT':
                    sender = packet['from']
                    if sender in self.approved_connections:
                        self.approved_connections.remove(sender)
                        sys.stdout.write(f"\r\n[!] '{sender}' disconnected from the chat.\n> ")
                        sys.stdout.flush()

                # 5. INCOMING CHAT MESSAGE
                elif msg_type == 'CHAT':
                    sender = packet['from']

                    if sender not in self.approved_connections:
                        continue

                    message = packet['message']
                    sent_time = packet['timestamp']
                    msg_length = packet['length']
                    transit_time_ms = (time.time() - sent_time) * 1000

                    sys.stdout.write(f"\r[{sender}] (Len: {msg_length}, Delay: {transit_time_ms:.1f}ms): {message}\n> ")
                    sys.stdout.flush()

            except OSError as e:
                if e.winerror == 10054: continue
            except:
                pass

    def start(self):
        self.sock.bind(('0.0.0.0', 0))

        print("--- RELAY CHAT CLIENT ---")
        self.name = input("Enter your username: ").strip()

        threading.Thread(target=self._listen, daemon=True).start()
        threading.Thread(target=self._send_heartbeat, daemon=True).start()

        print("\nCommands:")
        print("  /users           -> View all online users")
        print("  /connect <name>  -> Ask to chat with a specific user")
        print("  /connectall      -> Ask to chat with EVERYONE online")
        print("  /accept <name>   -> Approve someone's request")
        print("  /disconnect <nm> -> Close a connection")
        print("  /msg <name> <txt>-> Send a message to a specific user")
        print("--------------------------------------------------")
        print("> ", end="", flush=True)

        while True:
            cmd = input("")
            if not cmd:
                print("> ", end="", flush=True)
                continue

            parts = cmd.split(" ", 2)
            action = parts[0].lower()

            try:
                if action == '/users':
                    user_str = ", ".join(self.online_users) if self.online_users else "None"
                    print(f"[*] Online users: {user_str}")

                elif action == '/connect' and len(parts) >= 2:
                    target = parts[1]
                    packet = ChatProtocol.build_connect_request(self.name, target)
                    self.sock.sendto(packet, (SERVER_PUBLIC_DNS, SERVER_PUBLIC_PORT))
                    print(f"[*] Request sent to {target}.")

                # NEW: Connect to everyone at once
                elif action == '/connectall':
                    if not self.online_users:
                        print("[!] No other users are currently online.")
                    else:
                        for target in self.online_users:
                            packet = ChatProtocol.build_connect_request(self.name, target)
                            self.sock.sendto(packet, (SERVER_PUBLIC_DNS, SERVER_PUBLIC_PORT))
                        print(f"[*] Sent connection requests to {len(self.online_users)} user(s).")

                elif action == '/accept' and len(parts) >= 2:
                    target = parts[1]
                    self.approved_connections.add(target)
                    packet = ChatProtocol.build_connect_accept(self.name, target)
                    self.sock.sendto(packet, (SERVER_PUBLIC_DNS, SERVER_PUBLIC_PORT))
                    print(f"[*] You accepted {target}. You can now chat.")

                elif action == '/disconnect' and len(parts) >= 2:
                    target = parts[1]
                    if target in self.approved_connections:
                        self.approved_connections.remove(target)
                        packet = ChatProtocol.build_disconnect(self.name, target)
                        self.sock.sendto(packet, (SERVER_PUBLIC_DNS, SERVER_PUBLIC_PORT))
                        print(f"[*] You disconnected from {target}.")
                    else:
                        print(f"[!] You aren't connected to {target}.")

                elif action == '/msg' and len(parts) >= 3:
                    target = parts[1]
                    text = parts[2]

                    if target not in self.approved_connections:
                        print(f"[!] You cannot message {target} until connections are mutually approved.")
                    else:
                        packet = ChatProtocol.build_chat(self.name, target, text)
                        self.sock.sendto(packet, (SERVER_PUBLIC_DNS, SERVER_PUBLIC_PORT))
                else:
                    print("[!] Unknown or incomplete command.")
            except Exception as e:
                print(f"[!] Error sending command: {e}")

            print("> ", end="", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode = sys.argv[1]
    else:
        mode = input("Select mode (server/client): ").strip().lower()

    if mode == 'server':
        ChatRelayServer().start()
    elif mode == 'client':
        ChatRelayClient().start()