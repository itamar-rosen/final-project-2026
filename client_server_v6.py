import socket
import threading
import json
import requests
import time
import sys
import subprocess
import re
import os
import signal

# --- CONFIGURATION ---
APP_ID = "p2p_chats6"  # Change this to be unique!

# Ports must match your Playit.gg Dashboard
SERVER_LOCAL_TCP_PORT = 25565
SERVER_LOCAL_UDP_PORT = 19132
CLIENT_UDP_PORT = 5001


# ---------------------
# ROBUST AUTOMATION (Unbuffered Byte Stream)
# ---------------------
class PlayitRunner:
    def __init__(self, executable_path="playit"):
        self.exe = executable_path
        self.tcp_addr = None
        self.udp_addr = None
        self.process = None

    def find_executable(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        potential_names = ["playit.exe", "playit", "playit-windows-amd64.exe"]
        for name in potential_names:
            full_path = os.path.join(script_dir, name)
            if os.path.exists(full_path):
                return full_path
        return None

    def start_and_grab_addresses(self):
        cmd = self.find_executable()
        if not cmd:
            raise FileNotFoundError("Missing playit.exe")

        print(f"[Auto-Playit] Launching {cmd}...")
        print("[Auto-Playit] Mode: Unbuffered (Text appears instantly)...")
        print("----------------------------------------------------------------")

        # bufsize=0 forces Unbuffered mode.
        # We read raw bytes so we never get stuck waiting for a newline.
        self.process = subprocess.Popen(
            [cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0
        )

        # Regex patterns for your specific domains
        tcp_pattern = re.compile(r'([a-zA-Z0-9.-]+\.joinmc\.link)')
        udp_pattern = re.compile(r'([a-zA-Z0-9.-]+\.ply\.gg):(\d+)')
        claim_pattern = re.compile(r'(https://playit\.gg/claim/[a-zA-Z0-9-]+)')

        # Buffer to hold text for scanning
        text_buffer = ""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        start_time = time.time()

        while True:
            if time.time() - start_time > 60:
                print("\n[!] Scan timed out.")
                break

            # Read 1 byte at a time
            byte = self.process.stdout.read(1)
            if not byte:
                # If process died, stop
                if self.process.poll() is not None: break
                time.sleep(0.001)
                continue

            # 1. PRINT IMMEDIATELY (Raw)
            # We write directly to the console buffer to avoid lag/missing chars
            try:
                sys.stdout.buffer.write(byte)
                sys.stdout.flush()
            except:
                pass

            # 2. DECODE FOR SCANNING
            # We ignore errors so weird bytes don't crash the script
            try:
                char = byte.decode('utf-8', errors='ignore')
                text_buffer += char
                # Keep buffer small so regex is fast
                if len(text_buffer) > 500: text_buffer = text_buffer[-500:]
            except:
                continue

            # Clean colors for regex matching
            clean_text = ansi_escape.sub('', text_buffer)

            # --- SEARCH LOGIC ---

            # Check for NEW COMPUTER (Claim Link)
            if "claim" in clean_text:
                match = claim_pattern.search(clean_text)
                if match:
                    print("\n" + "=" * 50)
                    print("[!] NEW COMPUTER DETECTED")
                    print(f"[!] Link: {match.group(1)}")
                    print("=" * 50 + "\n")
                    text_buffer = ""  # Clear to prevent spam

            # Check for TCP (joinmc.link)
            if not self.tcp_addr:
                match = tcp_pattern.search(clean_text)
                if match:
                    domain = match.group(1)
                    self.tcp_addr = f"{domain}:25565"
                    print(f"\n\n[!!!] LOCKED TCP: {self.tcp_addr}")

            # Check for UDP (ply.gg)
            if not self.udp_addr:
                match = udp_pattern.search(clean_text)
                if match:
                    domain = match.group(1)
                    port = match.group(2)
                    self.udp_addr = f"{domain}:19132"
                    print(f"\n[!!!] LOCKED UDP: {self.udp_addr}")

            if self.tcp_addr and self.udp_addr:
                break

        return self.tcp_addr, self.udp_addr


# ---------------------
# SIGNALING
# ---------------------
class SignalingManager:
    def __init__(self, app_id):
        self.publish_url = f"https://ntfy.sh/{app_id}"
        self.poll_url = f"https://ntfy.sh/{app_id}/json"

    def publish_server_config(self, tcp_addr, udp_addr):
        data = json.dumps({"tcp": tcp_addr, "udp": udp_addr})
        try:
            requests.post(self.publish_url, data=data, timeout=5)
            print(f"[Signaling] Published to {self.publish_url}")
        except:
            pass

    def fetch_server_config(self):
        print(f"[Signaling] Connecting to {self.publish_url}...")
        try:
            res = requests.get(f"{self.poll_url}?poll=1", timeout=10)
            for line in res.iter_lines():
                if line:
                    data = json.loads(line)
                    if data.get('event') == 'message':
                        return json.loads(data['message'])
            raise ValueError("No address found.")
        except Exception as e:
            raise ConnectionError(f"Server not found: {e}")


# ---------------------
# SERVER
# ---------------------
class IntroducerServer:
    def __init__(self):
        self.peers = {}
        self.running = True
        self.signaling = SignalingManager(APP_ID)
        self.playit_runner = PlayitRunner()
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _broadcast_new_peer(self, new_peer_socket):
        if new_peer_socket not in self.peers: return
        new_peer_data = self.peers[new_peer_socket]
        msg = json.dumps({"type": "NEW_PEER", "peer": new_peer_data}).encode()
        for conn in self.peers:
            if conn != new_peer_socket:
                try:
                    conn.send(msg)
                except:
                    pass

    def _send_peer_list(self, target_socket):
        existing_peers = [p for s, p in self.peers.items() if s != target_socket]
        msg = json.dumps({"type": "PEER_LIST", "peers": existing_peers}).encode()
        target_socket.send(msg)

    def _listen_udp_stun(self):
        try:
            self.udp_sock.bind(('0.0.0.0', SERVER_LOCAL_UDP_PORT))
        except:
            return

        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(1024)
                msg = data.decode()
                if msg == 'WHO_AM_I':
                    reply = f"{addr[0]}:{addr[1]}"
                    self.udp_sock.sendto(reply.encode(), addr)
            except:
                pass

    def _handle_client_tcp(self, conn, addr):
        print(f"[Server] Connected: {addr}")
        try:
            while self.running:
                data = conn.recv(1024)
                if not data: break
                msg = json.loads(data.decode())
                if msg['type'] == 'REGISTER':
                    self.peers[conn] = {"ip": msg['public_ip'], "port": msg['udp_port'], "id": msg['id']}
                    self._send_peer_list(conn)
                    self._broadcast_new_peer(conn)
        except:
            pass
        finally:
            if conn in self.peers: del self.peers[conn]
            conn.close()

    def start(self):
        print("--- SERVER STARTING ---")
        try:
            tcp, udp = self.playit_runner.start_and_grab_addresses()
            print(f"[*] Addresses:\n    TCP: {tcp}\n    UDP: {udp}")
            self.signaling.publish_server_config(tcp, udp)
        except Exception as e:
            print(f"[!] Error: {e}")
            return

        try:
            self.tcp_sock.bind(('0.0.0.0', SERVER_LOCAL_TCP_PORT))
            self.tcp_sock.listen()
        except OSError:
            print(f"[!] ERROR: Port {SERVER_LOCAL_TCP_PORT} is busy.")
            return

        threading.Thread(target=self._listen_udp_stun, daemon=True).start()

        print("[*] Server is Ready. Waiting for friends...")
        while self.running:
            conn, addr = self.tcp_sock.accept()
            threading.Thread(target=self._handle_client_tcp, args=(conn, addr)).start()


# ---------------------
# CLIENT
# ---------------------
class P2PClient:
    def __init__(self, udp_port):
        self.udp_port = udp_port
        self.signaling = SignalingManager(APP_ID)
        self.known_peers = []
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _get_public_socket_info_from_server(self, udp_address_string):
        if ":" in udp_address_string:
            host, port = udp_address_string.split(':')
            port = int(port)
        else:
            host = udp_address_string
            port = 19132

        print(f"[*] Checking STUN at {host}:{port}...")
        self.udp_sock.settimeout(5)
        try:
            self.udp_sock.sendto(b'WHO_AM_I', (host, port))
            data, _ = self.udp_sock.recvfrom(1024)
            reply = data.decode()
            ip, port_str = reply.split(':')
            return ip, int(port_str)
        except:
            return "127.0.0.1", self.udp_port

    def _punch_hole(self, target_ip, target_port):
        for _ in range(5):
            self.udp_sock.sendto(b'HOLE_PUNCH', (target_ip, target_port))
            time.sleep(0.1)

    def _listen_udp(self):
        while True:
            try:
                data, addr = self.udp_sock.recvfrom(1024)
                if data.decode() not in ['HOLE_PUNCH', 'WHO_AM_I']:
                    print(f"\n[Peer {addr[0]}]: {data.decode()}\n>", end="")
            except:
                pass

    def send_message(self, msg, target_ip, target_port):
        self.udp_sock.sendto(msg.encode(), (target_ip, target_port))

    def _listen_tcp(self):
        while True:
            try:
                data = self.tcp_sock.recv(4096)
                if not data:
                    print("[-] Disconnected")
                    sys.exit()
                msg = json.loads(data.decode())
                if msg['type'] == 'PEER_LIST':
                    for p in msg['peers']:
                        self.known_peers.append(p)
                        threading.Thread(target=self._punch_hole, args=(p['ip'], p['port'])).start()
                elif msg['type'] == 'NEW_PEER':
                    p = msg['peer']
                    self.known_peers.append(p)
                    print(f"\n[*] New Peer Joined: {p['ip']}")
                    threading.Thread(target=self._punch_hole, args=(p['ip'], p['port'])).start()
            except:
                break

    def start(self):
        self.udp_sock.bind(('0.0.0.0', self.udp_port))
        print(f"[*] UDP Socket Bound to {self.udp_port}")

        # AUTOMATICALLY FIND SERVER
        print("[*] Finding Server via Signaling...")
        try:
            config = self.signaling.fetch_server_config()
            tcp_addr = config['tcp']
            udp_addr = config['udp']
        except Exception as e:
            print(f"[-] Could not find server: {e}")
            return

        public_ip, public_port = self._get_public_socket_info_from_server(udp_addr)
        print(f"[*] Resolved Public IP: {public_ip}:{public_port}")

        if ":" in tcp_addr:
            host, port = tcp_addr.split(':')
            port = int(port)
        else:
            host = tcp_addr
            port = 25565

        self.tcp_sock.connect((host, port))

        client_id = (int(str(public_ip).replace('.', '')[:5]) + public_port)
        reg = {"type": "REGISTER", "public_ip": public_ip, "udp_port": public_port, "id": client_id}
        self.tcp_sock.send(json.dumps(reg).encode())

        threading.Thread(target=self._listen_udp, daemon=True).start()
        threading.Thread(target=self._listen_tcp, daemon=True).start()

        print(f"\nYour ID: {client_id}\n")
        ids_string = input("Enter IDs to connect to: ")
        ids_list = ids_string.split(" ")

        while True:
            msg = input("\nEnter message: ")
            for target_id in ids_list:
                for p in self.known_peers:
                    if str(p['id']) == target_id:
                        self.send_message(msg, p['ip'], p['port'])


if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode = sys.argv[1]
    else:
        mode = input("Select mode (server/client): ").strip().lower()

    if mode == 'server':
        IntroducerServer().start()
    elif mode == 'client':
        P2PClient(CLIENT_UDP_PORT).start()
    else:
        print("Invalid mode.")