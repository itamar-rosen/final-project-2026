import socket, threading, struct, base64, subprocess, sys, json
from protocol import SecurityEngine


def install_server():
    try:
        from pyngrok import ngrok
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyngrok"])


install_server()
from pyngrok import ngrok, conf


class MasterServer:
    REGIONS = {'us': 0, 'eu': 1, 'ap': 2, 'au': 3, 'sa': 4, 'jp': 5, 'in': 6}

    def __init__(self, token, port=19132):
        self.port = port
        self.users = {}  # {name: {"sock": s, "pub": p}}
        self.groups = {}  # {gid: {"admin": name, "members": [], "muted": []}}
        self.proto = SecurityEngine()
        conf.get_default().auth_token = token

    def _make_code(self, url):
        clean = url.replace("tcp://", "")
        addr, port = clean.split(":")
        parts = addr.split(".")
        host_idx = int(parts[0])
        region_id = 99
        if len(parts) >= 4 and parts[2] in self.REGIONS:
            region_id = self.REGIONS[parts[2]]
        packed = struct.pack("!BBHH", region_id, host_idx, int(port), 77)
        return base64.urlsafe_b64encode(packed).decode().replace("=", "")

    def start(self):
        tun = ngrok.connect(self.port, "tcp")
        print(f"[*] SERVER LIVE | URL: {tun.public_url}")
        print(f"[*] JOIN CODE: {self._make_code(tun.public_url)}")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', self.port));
        s.listen(100)
        while True:
            c, a = s.accept()
            threading.Thread(target=self.client_handler, args=(c,)).start()

    def client_handler(self, conn):
        my_name = ""
        try:
            target, p_type, gid, payload = self.proto.receive(conn)
            my_name = target
            data = json.loads(payload.decode())
            self.users[my_name] = {"sock": conn, "pub": data['pub']}

            for name, info in self.users.items():
                info["sock"].sendall(self.proto.wrap("SERVER", 1, "LOBBY", f"{my_name} joined.".encode()))

            while True:
                target, p_type, gid, data = self.proto.receive(conn)
                if not target: break
                if p_type == 1:
                    self.process_admin(my_name, data.decode(), gid)
                elif p_type == 2:  # Handshake Request
                    if target in self.users: self.users[target]["sock"].sendall(self.proto.wrap(my_name, 2, gid, data))
                elif p_type == 0:  # Relay
                    group = self.groups.get(gid)
                    if group and my_name in group['members'] and my_name not in group['muted']:
                        for m in group['members']:
                            if m != my_name and m in self.users:
                                self.users[m]["sock"].sendall(self.proto.wrap(my_name, 0, gid, data))
                    elif target in self.users:
                        self.users[target]["sock"].sendall(self.proto.wrap(my_name, 0, gid, data))
        except:
            pass
        finally:
            if my_name in self.users: self.users.pop(my_name)

    def process_admin(self, sender, cmd_json, gid):
        try:
            cmd = json.loads(cmd_json);
            act = cmd.get('a')
            if act == "CREATE":
                self.groups[gid] = {"admin": sender, "members": [sender], "muted": []}
            elif act == "JOIN":
                if gid in self.groups: self.groups[gid]["members"].append(sender)
            elif act == "LEAVE":
                if gid in self.groups and sender in self.groups[gid]["members"]: self.groups[gid]["members"].remove(
                    sender)
            elif act == "GET_LOBBY":
                res = json.dumps({u: info["pub"] for u, info in self.users.items()}).encode()
                self.users[sender]["sock"].sendall(self.proto.wrap("SERVER", 1, "LOBBY", res))
            elif act in ["KICK", "MUTE"] and gid in self.groups and self.groups[gid]["admin"] == sender:
                t = cmd.get('t')
                if act == "KICK" and t in self.groups[gid]["members"]:
                    self.groups[gid]["members"].remove(t)
                elif act == "MUTE":
                    self.groups[gid]["muted"].append(t)
        except:
            pass


if __name__ == "__main__":
    MasterServer("36hGdlUE12VDvyiSJXJZBmhzXdv_2rN8nrso1JCdUPwtm259W").start()