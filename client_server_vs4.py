import socket
import threading
import json
import requests
import time
import sys
import subprocess
import re
import os

APP_ID = "my-p2p-app-channel-v3"

# --- LOCAL PORTS (Must match your Playit Dashboard) ---
# TCP (Minecraft Java Tunnel) -> Local Port 25565
SERVER_LOCAL_TCP_PORT = 25565
# UDP (Minecraft Bedrock Tunnel) -> Local Port 19132
SERVER_LOCAL_UDP_PORT = 19132

CLIENT_UDP_PORT = 5001
CONFIG_FILE = "server_config.json"


# ---------------------
# ROBUST AUTOMATION + SAVE SYSTEM
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

    def load_saved_config(self):
        """Checks if we already saved the addresses previously."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    print(f"[Config] Loaded saved addresses! Skipping scan.")
                    return data.get('tcp'), data.get('udp')
            except:
                pass
        return None, None

    def save_config(self, tcp, udp):
        """Saves addresses so we never have to scan/type them again."""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump({"tcp": tcp, "udp": udp}, f)
            print(f"[Config] Addresses saved to {CONFIG_FILE}. Next run will be instant!")
        except:
            pass

    def start_and_grab_addresses(self):
        # 1. CHECK SAVED CONFIG (The "Fast" Path)
        saved_tcp, saved_udp = self.load_saved_config()

        # We still need to launch Playit, even if we know the addresses
        cmd = self.find_executable()
        if not cmd:
            raise FileNotFoundError("Missing playit.exe")

        print(f"[Auto-Playit] Launching {cmd}...")

        # Launch Playit in background
        self.process = subprocess.Popen(
            [cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0
        )

        # If we already have the addresses from the file, return them immediately!
        if saved_tcp and saved_udp:
            print("[Auto-Playit] Using saved configuration. Starting server...")
            return saved_tcp, saved_udp

        # 2. START SCANNING (The "First Run" Path)
        print("[Auto-Playit] No config file found. Scanning output for tunnels...")
        print("[Auto-Playit] (Looking for .link, .gg, .ply.gg domains)")

        # Matches: domain.com OR domain.com:12345
        addr_pattern = re.compile(r'([a-zA-Z0-9.-]+\.(?:gg|link|net|com|org|io|ply\.gg))(?::(\d+))?')
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

        buffer = ""
        start_time = time.time()

        while self.process.poll() is None:
            # Timeout after 25 seconds
            if time.time() - start_time > 25:
                print("\n[!] Scan timed out.")
                break

            char = self.process.stdout.read(1)
            if not char:
                time.sleep(0.01)
                continue

            try:
                # Print output to screen so you can see it working
                sys.stdout.buffer.write(char)
                sys.stdout.flush()

                text_chunk = char.decode('utf-8', errors='ignore')
                buffer += text_chunk
                if len(buffer) > 2000: buffer = buffer[-2000:]
            except:
                continue

            clean_buffer = ansi_escape.sub('', buffer)

            # FIND TCP (looks for "TCP" and a domain)
            if not self.tcp_addr and "TCP" in clean_buffer:
                # Search strictly in the new text we just received
                match = addr_pattern.search(clean_buffer[clean_buffer.rfind("TCP"):])
                if match:
                    domain = match.group(1)
                    port = match.group(2)
                    if not port: port = "25565"  # Default for .joinmc.link
                    self.tcp_addr = f"{domain}:{port}"
                    print(f"\n\n[!!!] CAPTURED TCP: {self.tcp_addr}\n")

            # FIND UDP (looks for "UDP" and a domain)
            if not self.udp_addr and "UDP" in clean_buffer:
                match = addr_pattern.search(clean_buffer[clean_buffer.rfind("UDP"):])
                if match:
                    domain = match.group(1)
                    port = match.group(2)
                    if not port: port = "19132"
                    self.udp_addr = f"{domain}:{port}"
                    print(f"\n\n[!!!] CAPTURED UDP: {self.udp_addr}\n")

            if self.tcp_addr and self.udp_addr:
                break

        # 3. FALLBACK (Manual Entry - ONLY ONCE)
        if not self.tcp_addr or not self.udp_addr:
            print("\n\n[!] Could not auto-detect addresses from the messy text.")
            print("Please enter them manually just this ONE time.")
            print("I will save them so you never have to do this again.")

            if not self.tcp_addr: self.tcp_addr = input("Enter TCP Address (from website): ").strip()
            if not self.udp_addr: self.udp_addr = input("Enter UDP Address (from website): ").strip()

        # Save for next time
        self.save_config(self.tcp_addr, self.udp_addr)
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
            print(f"[Signaling] Config published to: {self.publish_url}")
        except Exception as e:
            print(f"[Signaling] Error publishing: {e}")

    def fetch_server_config(self):
        print(f"[Signaling] Looking for server at {self.publish_url}...")
        try:
            res = requests.get(f"{self.poll_url}?poll=1", timeout=5)
            for line in res.iter_lines():
                if line:
                    data = json.loads(line)
                    if data.get('event') == 'message':
                        return json.loads(data['message'])
            raise ValueError("No address found.")
        except Exception as e:
            raise ConnectionError(f"Could not retrieve server config: {e}")


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
        print(f"[*] STUN/UDP Listener active on local port {SERVER_LOCAL_UDP_PORT}")
        try:
            self.udp_sock.bind(('0.0.0.0', SERVER_LOCAL_UDP_PORT))
        except OSError:
            print(f"[!] ERROR: Port {SERVER_LOCAL_UDP_PORT} is in use! Close your actual Minecraft server.")
            return

        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(1024)
                msg = data.decode()
                if msg == 'WHO_AM_I':
                    reply = f"{addr[0]}:{addr[1]}"
                    self.udp_sock.sendto(reply.encode(), addr)
                    print(f"[STUN] Resolved Client {addr} -> {reply}")
            except Exception as e:
                print(f"[STUN] Error: {e}")

    def _handle_client_tcp(self, conn, addr):
        print(f"[Server] New TCP connection from {addr}")
        try:
            while self.running:
                data = conn.recv(1024)
                if not data: break
                msg = json.loads(data.decode())
                if msg['type'] == 'REGISTER':
                    self.peers[conn] = {"ip": msg['public_ip'], "port": msg['udp_port'], "id": msg['id']}
                    print(f"[Server] Registered User: {msg['public_ip']}:{msg['udp_port']}")
                    self._send_peer_list(conn)
                    self._broadcast_new_peer(conn)
        except:
            pass
        finally:
            if conn in self.peers: del self.peers[conn]
            conn.close()

    def start(self):
        print("--- AUTOMATED SERVER START ---")
        try:
            tcp_addr, udp_addr = self.playit_runner.start_and_grab_addresses()
            print(f"[*] Acquired: TCP={tcp_addr} | UDP={udp_addr}")
        except Exception as e:
            print(f"[!] Automation Error: {e}")
            return

        self.signaling.publish_server_config(tcp_addr, udp_addr)

        print(f"[*] Starting TCP Listener on {SERVER_LOCAL_TCP_PORT}...")
        try:
            self.tcp_sock.bind(('0.0.0.0', SERVER_LOCAL_TCP_PORT))
            self.tcp_sock.listen()
        except OSError:
            print(f"[!] ERROR: Port {SERVER_LOCAL_TCP_PORT} is in use! Close your actual Minecraft server.")
            return

        threading.Thread(target=self._listen_udp_stun, daemon=True).start()

        print("[*] Server Running. Waiting for clients...")
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
        # Handle addresses without ports (default to 25565/19132)
        if ":" in udp_address_string:
            host, port = udp_address_string.split(':')
            port = int(port)
        else:
            host = udp_address_string
            port = 19132  # Default UDP

        print(f"[*] Asking Server STUN ({host}:{port}) for my public address...")
        self.udp_sock.settimeout(5)
        try:
            self.udp_sock.sendto(b'WHO_AM_I', (host, port))
            data, _ = self.udp_sock.recvfrom(1024)
            reply = data.decode()
            ip, port_str = reply.split(':')
            return ip, int(port_str)
        except Exception as e:
            print(f"[!] STUN Error: {e}")
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

        print("[*] Fetching Server Configuration...")
        try:
            config = self.signaling.fetch_server_config()
            tcp_addr = config['tcp']
            udp_addr = config['udp']
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return

        public_ip, public_port = self._get_public_socket_info_from_server(udp_addr)
        print(f"[*] NAT Resolved: You are {public_ip}:{public_port}")

        if ":" in tcp_addr:
            host, port = tcp_addr.split(':')
            port = int(port)
        else:
            host = tcp_addr
            port = 25565  # Default TCP

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