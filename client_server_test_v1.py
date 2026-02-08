import socket
import threading
import json
import time
import sys

# --- HARDCODED CONFIGURATION ---
# SERVER (Your Computer)
SERVER_LOCAL_TCP_PORT = 25564
SERVER_LOCAL_UDP_PORT = 19132

# PUBLIC INTERNET (Playit.gg)
PUBLIC_TCP_ADDR = "hotels-lift.gl.joinmc.link"
PUBLIC_TCP_PORT = 16153

PUBLIC_UDP_ADDR = "processing-webshots.gl.at.ply.gg"
PUBLIC_UDP_PORT = 12273


# -----------------------------
# SIMPLIFIED SERVER
# -----------------------------
class TestServer:
    def __init__(self):
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = True
        self.clients = {}

    def start(self):
        print(f"--- SERVER STARTED ---")
        # FORCE IPv4 (127.0.0.1) instead of 0.0.0.0
        print(f"[*] Binding STRICTLY to IPv4 Loopback...")
        print(f"    TCP: 127.0.0.1:{SERVER_LOCAL_TCP_PORT}")
        print(f"    UDP: 127.0.0.1:{SERVER_LOCAL_UDP_PORT}")
        print("----------------------")

        try:
            # CHANGE '0.0.0.0' to '127.0.0.1' here
            self.tcp_sock.bind(('0.0.0.0', SERVER_LOCAL_TCP_PORT))
            self.tcp_sock.listen()

            # CHANGE '0.0.0.0' to '127.0.0.1' here too
            self.udp_sock.bind(('0.0.0.0', SERVER_LOCAL_UDP_PORT))
        except Exception as e:
            print(f"[!] Bind Error: {e}")
            return

        # Start Listeners
        threading.Thread(target=self.listen_udp, daemon=True).start()

        while self.running:
            print("&&&&&&&&&")
            conn, addr = self.tcp_sock.accept()
            print(f"[TCP] New Connection from {addr}")
            threading.Thread(target=self.handle_tcp, args=(conn, addr), daemon=True).start()

    def listen_udp(self):
        print("[UDP] Listening for STUN requests...")
        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(1024)
                msg = data.decode()
                print(f"[UDP] Received '{msg}' from {addr}")

                if msg == 'WHO_AM_I':
                    # Reply with the sender's public IP
                    reply = f"YOU_ARE:{addr[0]}:{addr[1]}"
                    self.udp_sock.sendto(reply.encode(), addr)
                    print(f"[UDP] Replied to {addr}")
            except Exception as e:
                print(f"[UDP Error] {e}")

    def handle_tcp(self, conn, addr):
        try:
            conn.send(b"WELCOME_TO_SERVER")
            while True:
                data = conn.recv(1024)
                if not data: break
                print(f"[TCP] Received from {addr}: {data.decode()}")
        except:
            pass
        finally:
            conn.close()


# -----------------------------
# SIMPLIFIED CLIENT
# -----------------------------
class TestClient:
    def __init__(self, target_tcp, target_tcp_port, target_udp, target_udp_port):
        self.tcp_addr = (target_tcp, target_tcp_port)
        self.udp_addr = (target_udp, target_udp_port)
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def start(self):
        print(f"--- CLIENT STARTED ---")
        print(f"[*] Target Addresses:")
        print(f"    TCP: {self.tcp_addr}")
        print(f"    UDP: {self.udp_addr}")
        print("----------------------")

        # 1. TEST UDP (STUN)
        print("\n[1] Testing UDP (Playit Tunnel Check)...")
        self.udp_sock.settimeout(5)
        try:
            msg = b'WHO_AM_I'
            print(f"    Sending '{msg.decode()}' to {self.udp_addr}...")
            self.udp_sock.sendto(msg, self.udp_addr)

            data, _ = self.udp_sock.recvfrom(1024)
            print(f"    [SUCCESS] Server Replied: {data.decode()}")
        except socket.timeout:
            print("    [FAILED] UDP Timed Out. (Server didn't get it, or didn't reply)")
        except Exception as e:
            print(f"    [ERROR] {e}")

        # 2. TEST TCP
        print("\n[2] Testing TCP (Reliable Connection)...")
        try:
            self.tcp_sock.connect(self.tcp_addr)
            print("    [SUCCESS] Connected to Server via TCP!")
            welcome = self.tcp_sock.recv(1024)
            print(f"    Server says: {welcome.decode()}")

            self.tcp_sock.send(b"Hello from Client!")
        except Exception as e:
            print(f"    [FAILED] Could not connect TCP: {e}")

        print("\n--- TEST FINISHED ---")
        input("Press Enter to exit...")


# -----------------------------
# MAIN MENU
# -----------------------------
if __name__ == "__main__":
    print("1. Run SERVER (Host)")
    print("2. Run CLIENT (Test Localhost - 127.0.0.1)")
    print("3. Run CLIENT (Test Public Playit - REAL TEST)")

    choice = input("Select mode (1/2/3): ").strip()

    if choice == "1":
        # Run Server
        TestServer().start()

    elif choice == "2":
        # Localhost Client (Should always work)
        client = TestClient("127.0.0.1", SERVER_LOCAL_TCP_PORT, "127.0.0.1", SERVER_LOCAL_UDP_PORT)
        client.start()

    elif choice == "3":
        # Public Playit Client (Requires separate network/Hotspot)
        print("\n[!] WARNING: You must run this on a Different Network (e.g. Hotspot)")
        print("[!] If you run this on the same PC as the server, it will likely fail (Hairpin NAT).")
        input("Press Enter to acknowledge...")

        client = TestClient(PUBLIC_TCP_ADDR, PUBLIC_TCP_PORT, PUBLIC_UDP_ADDR, PUBLIC_UDP_PORT)
        client.start()