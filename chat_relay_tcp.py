import socket
import threading
import json
import time
import sys
import struct

# --- CONFIGURATION ---
SERVER_LOCAL_PORT = 19132

# !!! UPDATE THESE WITH YOUR NEW PLAYIT TCP TUNNEL DETAILS !!!
SERVER_PUBLIC_DNS = "hotels-lift.gl.at.ply.gg"
SERVER_PUBLIC_PORT = 16153


# ---------------------------------------------------------
# PROTOCOL (The Message Builder & TCP Framer)
# ---------------------------------------------------------
class ChatProtocol:
    """Handles creating, sending, and receiving framed TCP messages."""

    # Notice: No more @staticmethod. It now takes 'self'!
    def send_packet(self, sock, payload_dict):
        """Packs the dictionary into JSON, adds a 4-byte length header, and sends it."""
        try:
            # 1. Convert dictionary to bytes
            data_bytes = json.dumps(payload_dict).encode('utf-8')

            # 2. Pack the length into a 4-byte integer ('>I' means Big-Endian Unsigned Int)
            length_header = struct.pack('>I', len(data_bytes))

            # 3. Send header + data
            sock.sendall(length_header + data_bytes)
        except Exception as e:
            pass  # Socket closed or error

    def recv_packet(self, sock):
        """Reads the exact length header, then reads the exact message size."""
        # 1. Read exactly 4 bytes for the length header
        raw_msglen = self._recvall(sock, 4)
        if not raw_msglen:
            return None

        # 2. Unpack the 4 bytes into an integer
        msglen = struct.unpack('>I', raw_msglen)[0]

        # 3. Read exactly 'msglen' bytes for the actual data
        data = self._recvall(sock, msglen)
        if not data:
            return None

        return json.loads(data.decode('utf-8', errors='ignore'))

    def _recvall(self, sock, n):
        """Helper to ensure we read exactly 'n' bytes from the TCP stream."""
        data = bytearray()
        while len(data) < n:
            try:
                packet = sock.recv(n - len(data))
                if not packet:
                    return None  # Connection closed
                data.extend(packet)
            except:
                return None
        return data


# ---------------------------------------------------------
# MESSAGE HANDLER (Processes UI & Routing logic)
# ---------------------------------------------------------
class MessageHandler:
    def __init__(self, node):
        self.node = node  # Reference to the Client or Server

    def handle_server(self, packet, client_sock):
        """Server-side routing logic"""
        msg_type = packet.get('type')
        sender_name = packet.get('from')

        if msg_type == 'REGISTER':
            name = packet['name']
            self.node.clients[name] = client_sock
            print(f"[+] '{name}' joined the server.")
            self.node.broadcast_user_list()

        # Route requests, accepts, disconnects, and chats to the target
        elif msg_type in ['CONNECT_REQUEST', 'CONNECT_ACCEPT', 'DISCONNECT', 'CHAT']:
            target_name = packet.get('to')
            if target_name in self.node.clients:
                target_sock = self.node.clients[target_name]

                # Use the server's protocol object to send the packet
                self.node.protocol.send_packet(target_sock, packet)

                if msg_type != 'CHAT':
                    print(f"[*] Routed {msg_type}: {sender_name} -> {target_name}")

    def handle_client(self, packet):
        """Client-side UI logic"""
        msg_type = packet.get('type')

        if msg_type == 'USER_LIST':
            users = packet['users']
            self.node.online_users = users
            sys.stdout.write(f"\r\n[Server] Online Users: {', '.join(users) if users else 'None'}\n> ")
            sys.stdout.flush()

        elif msg_type == 'CONNECT_REQUEST':
            sender = packet['from']
            sys.stdout.write(f"\r\n[!] REQUEST: '{sender}' wants to chat. Type '/accept {sender}'.\n> ")
            sys.stdout.flush()

        elif msg_type == 'CONNECT_ACCEPT':
            sender = packet['from']
            self.node.approved_connections.add(sender)
            sys.stdout.write(f"\r\n[!] '{sender}' accepted your request! You can now chat.\n> ")
            sys.stdout.flush()

        elif msg_type == 'DISCONNECT':
            sender = packet['from']
            if sender in self.node.approved_connections:
                self.node.approved_connections.remove(sender)
                sys.stdout.write(f"\r\n[!] '{sender}' disconnected.\n> ")
                sys.stdout.flush()

        elif msg_type == 'CHAT':
            sender = packet['from']
            if sender not in self.node.approved_connections:
                return

            message = packet['message']
            sent_time = packet['timestamp']
            msg_length = packet['length']
            transit_time_ms = (time.time() - sent_time) * 1000

            sys.stdout.write(f"\r[{sender}] (Len: {msg_length}, Delay: {transit_time_ms:.1f}ms): {message}\n> ")
            sys.stdout.flush()


# ---------------------------------------------------------
# SERVER (TCP Persistent Connections)
# ---------------------------------------------------------
class ChatTcpServer:
    def __init__(self):
        self.clients = {}  # { "username": socket_object }
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True

        # Instantiate the Handler and Protocol
        self.protocol = ChatProtocol()
        self.handler = MessageHandler(self)

    def broadcast_user_list(self):
        active_users = list(self.clients.keys())
        for name, client_sock in self.clients.items():
            others = [u for u in active_users if u != name]
            self.protocol.send_packet(client_sock, {"type": "USER_LIST", "users": others})

    def handle_client_thread(self, client_sock, addr):
        """Dedicated thread to read the continuous stream from one client"""
        client_name = None
        try:
            while self.running:
                packet = self.protocol.recv_packet(client_sock)
                if not packet:
                    break  # Client disconnected

                if packet.get('type') == 'REGISTER':
                    client_name = packet['name']

                self.handler.handle_server(packet, client_sock)
        except:
            pass
        finally:
            if client_name and client_name in self.clients:
                del self.clients[client_name]
                print(f"[-] '{client_name}' disconnected.")
                self.broadcast_user_list()
            client_sock.close()

    def start(self):
        print("--- TCP RELAY SERVER STARTED ---")
        try:
            self.sock.bind(('0.0.0.0', SERVER_LOCAL_PORT))
            self.sock.listen(5)
            print(f"[*] Listening on TCP: 0.0.0.0:{SERVER_LOCAL_PORT}")
        except Exception as e:
            print(f"[!] Bind Error: {e}")
            return

        while self.running:
            try:
                client_sock, addr = self.sock.accept()
                threading.Thread(target=self.handle_client_thread, args=(client_sock, addr), daemon=True).start()
            except:
                pass


# ---------------------------------------------------------
# CLIENT (TCP Stream)
# ---------------------------------------------------------
class ChatTcpClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.name = ""
        self.approved_connections = set()
        self.online_users = []

        # Instantiate the Handler and Protocol
        self.protocol = ChatProtocol()
        self.handler = MessageHandler(self)

    def _listen(self):
        """Reads the incoming TCP stream"""
        while self.running:
            packet = self.protocol.recv_packet(self.sock)
            if not packet:
                print("\n[!] Disconnected from server.")
                self.running = False
                break

            self.handler.handle_client(packet)

    def start(self):
        print("--- TCP RELAY CHAT CLIENT ---")
        self.name = input("Enter your username: ").strip()

        print(f"[*] Connecting to {SERVER_PUBLIC_DNS}:{SERVER_PUBLIC_PORT}...")
        try:
            self.sock.connect((SERVER_PUBLIC_DNS, SERVER_PUBLIC_PORT))
        except Exception as e:
            print(f"[!] Could not connect to Server: {e}")
            return

        # Register our name immediately
        self.protocol.send_packet(self.sock, {"type": "REGISTER", "name": self.name})

        # Start the listening thread
        threading.Thread(target=self._listen, daemon=True).start()

        print(
            "\nCommands: /users, /connect <name>, /connectall, /accept <name>, /disconnect <name>, /msg <name> <text>")
        print("> ", end="", flush=True)

        while self.running:
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
                    self.protocol.send_packet(self.sock, {"type": "CONNECT_REQUEST", "from": self.name, "to": parts[1]})
                    print(f"[*] Request sent to {parts[1]}.")

                elif action == '/connectall':
                    for target in self.online_users:
                        self.protocol.send_packet(self.sock,
                                                  {"type": "CONNECT_REQUEST", "from": self.name, "to": target})
                    print(f"[*] Sent connection requests to {len(self.online_users)} user(s).")

                elif action == '/accept' and len(parts) >= 2:
                    self.approved_connections.add(parts[1])
                    self.protocol.send_packet(self.sock, {"type": "CONNECT_ACCEPT", "from": self.name, "to": parts[1]})
                    print(f"[*] You accepted {parts[1]}.")

                elif action == '/disconnect' and len(parts) >= 2:
                    if parts[1] in self.approved_connections:
                        self.approved_connections.remove(parts[1])
                        self.protocol.send_packet(self.sock, {"type": "DISCONNECT", "from": self.name, "to": parts[1]})
                        print(f"[*] You disconnected from {parts[1]}.")

                elif action == '/msg' and len(parts) >= 3:
                    target = parts[1]
                    text = parts[2]
                    if target not in self.approved_connections:
                        print(f"[!] You cannot message {target} until mutually approved.")
                    else:
                        packet = {
                            "type": "CHAT",
                            "from": self.name,
                            "to": target,
                            "length": len(text),
                            "message": text,
                            "timestamp": time.time()
                        }
                        self.protocol.send_packet(self.sock, packet)
                else:
                    print("[!] Unknown or incomplete command.")
            except Exception:
                pass

            print("> ", end="", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode = sys.argv[1]
    else:
        mode = input("Select mode (server/client): ").strip().lower()

    if mode == 'server':
        ChatTcpServer().start()
    elif mode == 'client':
        ChatTcpClient().start()