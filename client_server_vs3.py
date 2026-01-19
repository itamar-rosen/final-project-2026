import socket
import threading
import json
import requests
import time
import sys

APP_ID = "my-p2p-app-channel-v3"

# Ports
SERVER_LOCAL_PORT = 9000  # The port Ngrok should point to
CLIENT_UDP_PORT = 5001  # The port clients chat on

ID_CONSTANT = 9
# ---------------------

class SignalingManager:

    def __init__(self, app_id):
        self.publish_url = f"https://ntfy.sh/{app_id}"
        self.poll_url = f"https://ntfy.sh/{app_id}/json"

    def get_local_ngrok_url(self):
        print("[Signaling] Scanning for local Ngrok tunnel...")
        for _ in range(5):
            try:
                res = requests.get("http://localhost:4040/api/tunnels", timeout=2)
                data = res.json()
                public_url = data['tunnels'][0]['public_url']
                clean_url = public_url.replace("tcp://", "")
                return clean_url
            except Exception:
                time.sleep(1)

        raise ConnectionError("Could not find Ngrok! Is 'ngrok tcp 9000' running?")

    def publish_server_address(self, address):
        """Post the address to ntfy.sh."""
        try:
            # We just POST the address (e.g. 0.tcp.ngrok.io:12345) as the body
            requests.post(self.publish_url, data=address, timeout=5)
            print(f"[Signaling] Address published to: {self.publish_url}")
        except Exception as e:
            print(f"[Signaling] Error publishing address: {e}")

    def fetch_server_address(self):
        """Fetch the latest address from ntfy.sh."""
        print(f"[Signaling] Looking for server at {self.publish_url}...")
        try:
            # We poll for the latest message
            res = requests.get(f"{self.poll_url}?poll=1", timeout=5)

            # ntfy sends a stream. We take the first valid message.
            for line in res.iter_lines():
                if line:
                    data = json.loads(line)
                    if data.get('event') == 'message':
                        full_addr = data['message']
                        host, port = full_addr.split(':')
                        return host, int(port)
            raise ValueError("No address found.")
        except Exception as e:
            raise ConnectionError(f"Could not retrieve server address: {e}")


class IntroducerServer:
    """
    The Server Logic.
    """

    def __init__(self, port):
        self.port = port
        self.peers = {}  # {socket_obj: {'ip': str, 'port': int}}
        self.running = True
        self.signaling = SignalingManager(APP_ID)

    def _broadcast_new_peer(self, new_peer_socket):
        new_peer_data = self.peers[new_peer_socket]
        msg = json.dumps({"type": "NEW_PEER", "peer": new_peer_data}).encode()
        for conn in self.peers:
            if conn != new_peer_socket:
                try:
                    conn.send(msg)
                except:
                    pass

    def _send_peer_list_id(self, target_socket):
        existing_peers = [p for s, p in self.peers.items() if s != target_socket]
        msg = json.dumps({"type": "PEER_LIST", "peers": existing_peers}).encode()
        target_socket.send(msg)



    def _handle_client(self, conn, addr):
        print(f"[Server] New connection from {addr}")

        try:
            while self.running:
                data = conn.recv(1024)
                if not data:
                    break
                msg = json.loads(data.decode())

                if msg['type'] == 'REGISTER':

                    self.peers[conn] = {"ip": msg['public_ip'], "port": msg['udp_port'], "id": msg['id']}
                    print(f"[Server] Registered User: {msg['public_ip']}:{msg['udp_port']}")
                    self._send_peer_list_id(conn)
                    self._broadcast_new_peer(conn)
        except:
            pass
        finally:
            if conn in self.peers:
                del self.peers[conn]
            conn.close()

    def start(self):
        # 1. Get Ngrok URL and Publish it
        try:
            ngrok_address = self.signaling.get_local_ngrok_url()
            self.signaling.publish_server_address(ngrok_address)
        except Exception as e:
            print(f"[!] Error: {e}")
            return

        # 2. Start TCP Listener
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', self.port))
        s.listen()
        print(f"[*] Server Online via Ngrok: {ngrok_address}")

        # 3. Heartbeat (Republish address every 60s)
        def heartbeat():
            while self.running:
                time.sleep(60)
                self.signaling.publish_server_address(ngrok_address)

        threading.Thread(target=heartbeat, daemon=True).start()

        while self.running:
            conn, addr = s.accept()
            threading.Thread(target=self._handle_client, args=(conn, addr)).start()


class P2PClient:
    """
    The Client Logic.
    """

    def __init__(self, udp_port):
        self.udp_port = udp_port
        self.signaling = SignalingManager(APP_ID)
        self.known_peers = []
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.att = None

    def _get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org').text
        except:
            return "127.0.0.1"

    def _punch_hole(self, target_ip, target_port):
        self.udp_sock.sendto(b'HOLE_PUNCH', (target_ip, target_port))

    def _listen_udp(self):
        self.udp_sock.bind(('0.0.0.0', self.udp_port))
        print(f"[*] UDP Listening on {self.udp_port}")
        while True:
            try:
                data, addr = self.udp_sock.recvfrom(1024)
                if data.decode() != 'HOLE_PUNCH':
                    print(f"\n[Peer {addr[0]}]: {data.decode()}")
            except:
                pass

    def send_message(self, msg, target_ip, target_port):
        self.udp_sock.sendto(msg.encode(), (target_ip, target_port))

    def _listen_tcp(self):
        while True:
            try:
                data = self.tcp_sock.recv(4096)
                if not data:
                    print("[-] Disconnected from Server")
                    sys.exit()
                self.att = msg = json.loads(data.decode())

                if msg['type'] == 'PEER_LIST':
                    for p in msg['peers']:
                        self.known_peers.append(p)
                        self._punch_hole(p['ip'], p['port'])
                elif msg['type'] == 'NEW_PEER':
                    p = msg['peer']
                    self.known_peers.append(p)
                    print(f"[*] New Peer Joined: {p['ip']}")
                    self._punch_hole(p['ip'], p['port'])
            except:
                break

    def _create_client_id(self, ip, port):
        ip_str = str(ip).replace(".", "")
        client_id = (int(ip_str) + port) * ID_CONSTANT
        return client_id

    def start(self):
        print("[*] Finding Server address...")
        try:
            server_ip, server_port = self.signaling.fetch_server_address()
            print(f"[*] Found Server at {server_ip}:{server_port}")
            self.tcp_sock.connect((server_ip, server_port))
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return

        my_ip = self._get_public_ip()
        print(f"[*] My Public IP: {my_ip}")
        client_id = self._create_client_id(my_ip, self.udp_port)
        reg = {"type": "REGISTER", "public_ip": my_ip, "udp_port": self.udp_port, "id": client_id}
        self.tcp_sock.send(json.dumps(reg).encode())

        threading.Thread(target=self._listen_udp, daemon=True).start()
        threading.Thread(target=self._listen_tcp, daemon=True).start()

        print(f"\nYour ID: {client_id}\n")
        print("\nEnter IDs that you would like to connect to.")
        
        ids_string = input()
        ids_list = ids_string.split(" ")
        num = 0
        while True:
            msg = input()
            for p in self.known_peers:
                if str(p['id']) == ids_list[num]:

                    self.send_message(msg, p['ip'], p['port'])
                num += 1


if __name__ == "__main__":
    # This logic handles the arguments, or asks you if you forgot them.
    if len(sys.argv) > 1:
        mode = sys.argv[1]
    else:
        mode = input("Select mode (server/client): ").strip().lower()

    if mode == 'server':
        IntroducerServer(SERVER_LOCAL_PORT).start()
    elif mode == 'client':
        P2PClient(CLIENT_UDP_PORT).start()
    else:
        print("Invalid mode. Use 'server' or 'client'.")