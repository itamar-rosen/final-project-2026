import socket, threading, base64, struct, subprocess, sys, json
from protocol import SecurityEngine


def install_client():
    try:
        from colorama import Fore, init
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])


install_client()
from colorama import Fore, init

init(autoreset=True)


class Client:
    def __init__(self):
        self.proto = SecurityEngine()
        self.priv, self.pub = self.proto.generate_rsa_keys()
        self.sessions = {}
        self.user_to_gid = {}
        self.lobby_keys = {}
        self.pending_reqs = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.user = ""

    def connect(self, code_or_url):
        try:
            if ":" in code_or_url:
                h, p = code_or_url.replace("tcp://", "").split(":")
                host, port = h, int(p)
            else:
                data = base64.urlsafe_b64decode(code_or_url + "==")
                reg_id, h_idx, port, salt = struct.unpack("!BBHH", data)
                regs = {0: 'us', 1: 'eu', 2: 'ap', 3: 'au', 4: 'sa', 5: 'jp', 6: 'in'}
                host = f"{h_idx}.tcp.{regs.get(reg_id, 'us')}.ngrok.io" if reg_id != 99 else f"{h_idx}.tcp.ngrok.io"

            self.sock.connect((host, port))
            reg = json.dumps({'pub': self.pub}).encode()
            self.sock.sendall(self.proto.wrap(self.user, 1, "REG", reg))
            threading.Thread(target=self.listen, daemon=True).start()
            return True
        except:
            return False

    def listen(self):
        while True:
            sender, p_type, gid, payload = self.proto.receive(self.sock)
            if not sender: break

            if p_type == 1:
                try:
                    data = json.loads(payload.decode())
                    if isinstance(data, dict):
                        self.lobby_keys = data
                        print(f"\r{Fore.CYAN}[SYSTEM] Online Users: {', '.join(self.lobby_keys.keys())}\n> ", end="")
                except:
                    print(f"\r{Fore.YELLOW}[SYSTEM] {payload.decode()}\n> ", end="")

            elif p_type == 2:
                req = json.loads(payload.decode())
                self.pending_reqs[sender] = req['pub']
                print(f"\r{Fore.GREEN}[!] {sender} wants to connect. Type: /accept {sender}\n> ", end="")

            elif p_type == 0:
                data = json.loads(payload.decode())
                if data['t'] == 'INV':
                    key = self.proto.rsa_decrypt(self.priv, base64.b64decode(data['k']))
                    self.sessions[data['g']] = key
                    self.user_to_gid[sender] = data['g']
                    self.sock.sendall(self.proto.wrap("SERVER", 1, data['g'], json.dumps({'a': 'JOIN'}).encode()))
                    print(f"\r{Fore.CYAN}[!] Secure Session established with {sender}. GID: {data['g']}\n> ", end="")

                elif data['t'] == 'MSG':
                    key = self.sessions.get(data['g'])
                    if key:
                        txt = self.proto.aes_decrypt(key, data['m'])
                        print(f"\r{Fore.MAGENTA}[{sender}] {Fore.WHITE}{txt}\n> ", end="")

                # FIX: Catch the disconnect signal from the other user
                elif data['t'] == 'CLOSE':
                    closed_gid = data['g']
                    disconnector = data.get('u', 'A member')
                    if closed_gid in self.sessions:
                        del self.sessions[closed_gid]

                        # Clean up the username mapping
                        to_delete = [u for u, g in self.user_to_gid.items() if g == closed_gid]
                        for u in to_delete:
                            del self.user_to_gid[u]

                        # Tell the server we are also leaving so the room is fully destroyed
                        self.sock.sendall(self.proto.wrap("SERVER", 1, closed_gid, json.dumps({'a': 'LEAVE'}).encode()))
                        print(f"\r{Fore.YELLOW}[!] {disconnector} disconnected. Session {closed_gid} closed.\n> ",
                              end="")

    def run(self):
        self.user = input("Username: ").strip()[:16]
        url = input("Join Code or URL: ").strip()

        if self.connect(url):
            print(
                f"\n{Fore.GREEN}Ready. Commands: /users, /connect [user], /accept [user], /msg [user/gid] [msg], /broadcast [msg], /disconnect [user/gid], /gids")

            while True:
                try:
                    raw_inp = input("> ").strip()
                    if not raw_inp: continue

                    inp = raw_inp.split(" ", 2)
                    cmd = inp[0].lower()

                    if cmd == "/users":
                        self.sock.sendall(
                            self.proto.wrap("SERVER", 1, "LOBBY", json.dumps({'a': 'GET_LOBBY'}).encode()))

                    elif cmd == "/gids":
                        print(f"Active GIDs: {list(self.sessions.keys())}")

                    elif cmd == "/connect":
                        if len(inp) < 2:
                            print(f"{Fore.RED}[!] Usage: /connect [user]")
                            continue
                        self.sock.sendall(self.proto.wrap(inp[1], 2, "REQ", json.dumps({'pub': self.pub}).encode()))
                        print(f"[*] Request sent to {inp[1]}...")

                    elif cmd == "/accept":
                        if len(inp) < 2:
                            print(f"{Fore.RED}[!] Usage: /accept [user]")
                            continue
                        target = inp[1]
                        if target in self.pending_reqs:
                            gid = f"Room_{target[:3]}_{self.user[:3]}"
                            aes_key = self.proto.generate_session_key()
                            self.sessions[gid] = aes_key
                            self.user_to_gid[target] = gid

                            self.sock.sendall(self.proto.wrap("SERVER", 1, gid, json.dumps({'a': 'CREATE'}).encode()))

                            enc = base64.b64encode(self.proto.rsa_encrypt(self.pending_reqs[target], aes_key)).decode()
                            self.sock.sendall(self.proto.wrap(target, 0, "SYSTEM",
                                                              json.dumps({'t': 'INV', 'g': gid, 'k': enc}).encode()))

                            print(f"[+] Accepted {target}. GID: {gid}")
                        else:
                            print(f"{Fore.RED}[!] No pending request from {target}.")

                    elif cmd == "/msg":
                        if len(inp) < 3:
                            print(f"{Fore.RED}[!] Usage: /msg [user/gid] [message]")
                            continue
                        target, txt = inp[1], inp[2]
                        gid = self.user_to_gid.get(target, target)
                        key = self.sessions.get(gid)
                        if key:
                            enc_msg = self.proto.aes_encrypt(key, txt)
                            self.sock.sendall(self.proto.wrap("GROUP", 0, gid, json.dumps(
                                {'t': 'MSG', 'g': gid, 'm': enc_msg}).encode()))
                        else:
                            print(f"{Fore.RED}[!] No secure session established with {target}.")

                    elif cmd == "/broadcast":
                        if len(inp) < 2:
                            print(f"{Fore.RED}[!] Usage: /broadcast [message]")
                            continue
                        for gid, k in self.sessions.items():
                            enc_msg = self.proto.aes_encrypt(k, inp[1])
                            self.sock.sendall(self.proto.wrap("GROUP", 0, gid, json.dumps(
                                {'t': 'MSG', 'g': gid, 'm': enc_msg}).encode()))

                    elif cmd in ["/kick", "/mute"]:
                        if len(inp) < 3:
                            print(f"{Fore.RED}[!] Usage: {cmd} [gid] [user]")
                            continue
                        self.sock.sendall(self.proto.wrap("SERVER", 1, inp[1],
                                                          json.dumps({'a': cmd[1:].upper(), 't': inp[2]}).encode()))

                    elif cmd == "/disconnect":
                        if len(inp) < 2:
                            print(f"{Fore.RED}[!] Usage: /disconnect [user/gid]")
                            continue
                        gid = self.user_to_gid.get(inp[1], inp[1])
                        if gid in self.sessions:
                            # FIX: Alert the group that we are closing the connection before we leave
                            self.sock.sendall(self.proto.wrap("GROUP", 0, gid, json.dumps(
                                {'t': 'CLOSE', 'g': gid, 'u': self.user}).encode()))

                            self.sock.sendall(self.proto.wrap("SERVER", 1, gid, json.dumps({'a': 'LEAVE'}).encode()))
                            del self.sessions[gid]

                            # Clean up our own mapping
                            to_delete = [u for u, g in self.user_to_gid.items() if g == gid]
                            for u in to_delete: del self.user_to_gid[u]

                            print(f"[*] Session {gid} closed.")
                        else:
                            print(f"{Fore.RED}[!] Session not found.")
                    else:
                        print(f"{Fore.RED}[!] Unknown command. Try /users, /connect, or /msg")

                except Exception as e:
                    print(f"{Fore.RED}[!] Command processing error: {e}")


if __name__ == "__main__":
    Client().run()