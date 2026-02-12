import socket
import threading
import json
import time
import sys

# --- CONFIGURATION ---
SERVER_LOCAL_PORT = 19132
SERVER_PUBLIC_DNS = "processing-webshots.gl.at.ply.gg"
SERVER_PUBLIC_PORT = 12273
CLIENT_BIND_PORT = 5001


# ---------------------------------------------------------
# SERVER (P2P Signal Hub) - UNCHANGED
# ---------------------------------------------------------
class UdpSignalingServer:
    def __init__(self):
        self.peers = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = True

    def start(self):
        print("--- UDP SERVER STARTED ---")
        try:
            self.sock.bind(('0.0.0.0', SERVER_LOCAL_PORT))
            print(f"[*] Listening on UDP: 0.0.0.0:{SERVER_LOCAL_PORT}")
        except Exception as e:
            print(f"[!] Bind Error: {e}")
            return

        print("[*] Waiting for Heartbeats...")

        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                msg_str = data.decode('utf-8', errors='ignore')

                # --- 1. HEARTBEAT & LIST REQUEST ---
                if msg_str.startswith('{'):
                    try:
                        msg = json.loads(msg_str)
                        if msg.get('type') == 'REGISTER':
                            client_id = msg['id']

                            if addr not in self.peers:
                                print(f"[+] New Peer: {addr} (ID: {client_id})")

                            self.peers[addr] = {'id': client_id, 'last_seen': time.time()}

                            # Clean old peers
                            current_time = time.time()
                            active_list = []
                            to_remove = []
                            for p_addr, p_info in self.peers.items():
                                if current_time - p_info['last_seen'] > 15:
                                    to_remove.append(p_addr)
                                else:
                                    active_list.append({
                                        'ip': p_addr[0],
                                        'port': p_addr[1],
                                        'id': p_info['id']
                                    })
                            for k in to_remove: del self.peers[k]

                            # Send List Back to Sender
                            reply = json.dumps({"type": "PEER_LIST", "peers": active_list})
                            self.sock.sendto(reply.encode(), addr)

                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                print(f"[!] Server Error: {e}")


# ---------------------------------------------------------
# CLIENT (Chat Mode)
# ---------------------------------------------------------
class UdpP2PClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.my_id = str(int(time.time() % 10000))
        self.known_peers = []
        self.running = True

        # Windows Fix
        if sys.platform == 'win32':
            try:
                self.sock.ioctl(socket.SIO_UDP_CONNRESET, False)
            except:
                pass

    def _punch_hole(self, target_ip, target_port):
        """Spam packets to open the route"""
        for _ in range(5):
            try:
                self.sock.sendto(b'HOLE_PUNCH', (target_ip, target_port))
            except:
                pass
            time.sleep(0.05)

    def _send_heartbeat(self):
        """Ping server every 2s"""
        # print("[*] Heartbeat Thread Started.")
        while self.running:
            msg = json.dumps({"type": "REGISTER", "id": self.my_id})
            try:
                self.sock.sendto(msg.encode(), (SERVER_PUBLIC_DNS, SERVER_PUBLIC_PORT))
            except:
                pass
            time.sleep(2)

    def _listen(self):
        # We use this to track if the peer count changed so we don't spam
        last_peer_count = -1

        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                text = data.decode('utf-8', errors='ignore')

                # 1. Check for Server List
                if "PEER_LIST" in text:
                    try:
                        json_start = text.find('{')
                        clean_json = text[json_start:]
                        msg = json.loads(clean_json)
                        server_list = msg['peers']

                        # Update Peer List
                        self.known_peers = []
                        for p in server_list:
                            if str(p['id']) != self.my_id:
                                self.known_peers.append(p)
                                # Punch hole
                                threading.Thread(target=self._punch_hole, args=(p['ip'], p['port'])).start()

                        # ONLY PRINT IF STATUS CHANGED
                        current_count = len(self.known_peers)
                        if current_count != last_peer_count:
                            if current_count > last_peer_count:
                                print(f"\n[+] New Peer Joined! (Total: {current_count})")
                            else:
                                print(f"\n[-] Peer Left. (Total: {current_count})")

                            print("> ", end="", flush=True)  # Restore prompt
                            last_peer_count = current_count

                    except Exception as e:
                        pass
                    continue

                # 2. Chat Message (Ignore internal messages)
                if "HOLE_PUNCH" not in text:
                    # Clear current line and print message nicely
                    sys.stdout.write(f"\r[Peer {addr[0]}]: {text}\n> ")
                    sys.stdout.flush()

            except OSError as e:
                if e.winerror == 10054: continue
            except Exception as e:
                print(f"[!] Receive Error: {e}")

    def start(self):
        print(f"--- CLIENT STARTED (ID: {self.my_id}) ---")

        try:
            self.sock.bind(('0.0.0.0', CLIENT_BIND_PORT))
        except:
            print(f"[!] Port {CLIENT_BIND_PORT} busy. Using random.")
            self.sock.bind(('0.0.0.0', 0))

        threading.Thread(target=self._listen, daemon=True).start()
        threading.Thread(target=self._send_heartbeat, daemon=True).start()

        print(f"[*] Connecting to {SERVER_PUBLIC_DNS}...")
        print("[*] Waiting for peers to join...")
        print("Type a message and press Enter.")
        print("> ", end="", flush=True)

        while True:
            msg = input("")

            # If empty input, just reprint prompt
            if not msg:
                print("> ", end="", flush=True)
                continue

            # Send to all peers
            for p in self.known_peers:
                try:
                    self.sock.sendto(msg.encode(), (p['ip'], p['port']))
                except:
                    pass

            # Reprint prompt after sending
            print("> ", end="", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode = sys.argv[1]
    else:
        mode = input("Select mode (server/client): ").strip().lower()

    if mode == 'server':
        UdpSignalingServer().start()
    elif mode == 'client':
        UdpP2PClient().start() 