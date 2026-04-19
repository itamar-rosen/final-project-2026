# remote_server.py
import sys
import subprocess
import os
import importlib.util
import socket
import threading
import time
import io

def check_and_install_packages():
    required_packages = {
        'pyautogui': 'pyautogui',
        'mss': 'mss',
        'PIL': 'Pillow'
    }
    missing_packages = []
    for import_name, package_name in required_packages.items():
        if importlib.util.find_spec(import_name) is None:
            missing_packages.append(package_name)

    if missing_packages:
        print(f"MISSING DEPENDENCIES: {', '.join(missing_packages)}")
        while True:
            response = input("Do you want to install them now? (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
                    print("Installation successful. Restarting server...")
                    os.execv(sys.executable, ['python'] + sys.argv)
                except Exception as e:
                    print(f"Error: {e}")
                    sys.exit(1)
            elif response in ['n', 'no']:
                print("Exiting.")
                sys.exit(0)

if __name__ == "__main__":
    check_and_install_packages()

import pyautogui
from remote_protocol import NetworkProtocol

try:
    import mss
    from PIL import Image, ImageDraw
    STREAMING_CAPABLE = True
except ImportError:
    STREAMING_CAPABLE = False

pyautogui.PAUSE = 0
pyautogui.FAILSAFE = False

class RemoteServer:
    def __init__(self):
        self.HOST = '0.0.0.0'
        self.CONTROL_PORT = 50505
        self.PASSWORD = "1"
        self.VIDEO_JPEG_QUALITY = 100
        self.VIDEO_SCALE_FACTOR = 1
        self.TARGET_FPS = 60
        self.SERVER_CURSOR_COLOR = (255, 0, 0, 200)
        self.SERVER_CURSOR_RADIUS = 6

        self.video_streams = {}
        self.video_streams_lock = threading.Lock()
        self.server_socket = None

    def execute_mouse_command(self, command):
        try:
            action = command.get('action')
            x, y = command.get('x'), command.get('y')
            button = command.get('button')

            if action == 'move':
                pyautogui.moveTo(x, y, duration=0)
            elif action == 'click':
                pyautogui.click(x=x, y=y, button=button)
            elif action == 'press':
                pyautogui.mouseDown(x=x, y=y, button=button)
            elif action == 'release':
                pyautogui.mouseUp(x=x, y=y, button=button)
            elif action == 'scroll':
                pyautogui.scroll(command.get('clicks', 0), x=x, y=y)
            else:
                return {"status": "error", "message": f"Unknown mouse action: {action}"}
            return {"status": "ok", "message": f"Mouse action '{action}' executed."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def execute_keyboard_command(self, command):
        try:
            key_name, action = command.get('key_name'), command.get('action')
            if action == 'write':
                pyautogui.typewrite(command.get('text', ''), interval=0.01)
            elif action == 'press':
                pyautogui.keyDown(key_name)
            elif action == 'release':
                pyautogui.keyUp(key_name)
            elif action == 'type':
                pyautogui.press(key_name)
            elif action == 'hotkey':
                pyautogui.hotkey(*command.get('keys', []))
            else:
                return {"status": "error", "message": f"Unknown keyboard action: {action}"}
            return {"status": "ok", "message": f"Keyboard action '{key_name}' executed."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def list_directory(self, path_to_list):
        try:
            normalized_path = os.path.abspath(path_to_list)
            if not (os.path.exists(normalized_path) and os.path.isdir(normalized_path)):
                return {"status": "error", "message": "Path does not exist.", "path": normalized_path}
            items = []
            for item_name in os.listdir(normalized_path):
                item_full_path = os.path.join(normalized_path, item_name)
                itype = "dir" if os.path.isdir(item_full_path) else "file"
                items.append({"name": item_name, "type": itype, "path": item_full_path})
            return {"status": "ok", "message": "Listed.", "listing": items, "path": normalized_path}
        except Exception as e:
            return {"status": "error", "message": str(e), "path": os.path.abspath(path_to_list)}

    def send_file_to_client(self, conn, file_path):
        abs_file_path = os.path.abspath(file_path)
        try:
            if not (os.path.exists(abs_file_path) and os.path.isfile(abs_file_path)):
                NetworkProtocol.send_error(conn, "File not found.")
                return

            file_size = os.path.getsize(abs_file_path)
            NetworkProtocol.send_success(conn, "Ready", filename=os.path.basename(abs_file_path), size=file_size)

            ack = NetworkProtocol.receive_json(conn)
            if ack.get("status") != "ready_to_receive":
                return

            with open(abs_file_path, 'rb') as f:
                NetworkProtocol.send_stream(conn, f, file_size)
        except Exception as e:
            print(f"Error sending file: {e}")

    def receive_file_from_client(self, conn, target_path, file_size):
        abs_target = os.path.abspath(target_path)
        try:
            os.makedirs(os.path.dirname(abs_target), exist_ok=True)
            NetworkProtocol.send_success(conn, "ready_to_receive", status="ready_to_receive")

            with open(abs_target, 'wb') as f:
                NetworkProtocol.receive_stream_to_file(conn, f, file_size)

            NetworkProtocol.send_success(conn, "File received.")
        except Exception as e:
            try:
                NetworkProtocol.send_error(conn, str(e))
            except:
                pass

    def execute_system_command(self, command_str):
        try:
            result = subprocess.run(command_str, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout or ""
            error_output = result.stderr or ""
            if result.returncode == 0:
                return {"status": "ok", "message": "Executed", "output": output or "Command executed."}
            else:
                return {"status": "error", "message": f"Code {result.returncode}:\n{output}\n{error_output}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def stream_screen_to_client(self, video_sock, client_addr, stop_event):
        if not STREAMING_CAPABLE: return

        try:
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                w = int(monitor["width"] * self.VIDEO_SCALE_FACTOR)
                h = int(monitor["height"] * self.VIDEO_SCALE_FACTOR)
                if w <= 0: w = 1
                if h <= 0: h = 1

                while not stop_event.is_set():
                    start_t = time.time()
                    sct_img = sct.grab(monitor)
                    img = Image.frombytes("RGB", (sct_img.width, sct_img.height), sct_img.rgb, "raw", "BGR")
                    img = img.convert("RGBA")

                    try:
                        cx, cy = pyautogui.position()
                        draw = ImageDraw.Draw(img)
                        r = self.SERVER_CURSOR_RADIUS
                        draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=self.SERVER_CURSOR_COLOR)
                    except: pass

                    if img.mode == 'RGBA': img = img.convert('RGB')
                    if self.VIDEO_SCALE_FACTOR != 1.0:
                        img = img.resize((w, h), Image.LANCZOS)

                    buf = io.BytesIO()
                    img.save(buf, format='JPEG', quality=self.VIDEO_JPEG_QUALITY)
                    frame_data = buf.getvalue()

                    try:
                        msg = NetworkProtocol.create_message(frame_data)
                        video_sock.sendall(msg)
                    except Exception:
                        break

                    elapsed = time.time() - start_t
                    sleep_t = (1.0 / self.TARGET_FPS) - elapsed
                    if sleep_t > 0: time.sleep(sleep_t)
        except Exception as e:
            print(f"Stream error: {e}")
        finally:
            if video_sock: video_sock.close()
            stop_event.set()

    def handle_client(self, conn, addr):
        addr_str = f"{addr[0]}:{addr[1]}"
        print(f"[{addr_str}] Connected.")

        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except: pass

        try:
            auth_msg = NetworkProtocol.receive_json(conn)
            if auth_msg and auth_msg.get("type") == "auth" and auth_msg.get("password") == self.PASSWORD:
                NetworkProtocol.send_success(conn, "Auth success.")
            else:
                NetworkProtocol.send_error(conn, "Auth failed.")
                return
        except Exception:
            return

        try:
            while True:
                command = NetworkProtocol.receive_json(conn)
                if not command: break

                cmd_type = command.get('type')
                response = None

                if cmd_type == 'mouse_event':
                    response = self.execute_mouse_command(command.get('data', {}))
                elif cmd_type == 'keyboard_event':
                    response = self.execute_keyboard_command(command.get('data', {}))
                elif cmd_type == 'list_dir':
                    response = self.list_directory(command.get('path', '.'))
                elif cmd_type == 'get_file':
                    self.send_file_to_client(conn, command.get('path'))
                    continue
                elif cmd_type == 'put_file_start':
                    self.receive_file_from_client(conn, command.get('path'), command.get('size'))
                    continue
                elif cmd_type == 'execute_command':
                    response = self.execute_system_command(command.get('command_str'))
                elif cmd_type == 'ping':
                    response = {"status": "ok", "message": "pong"}
                elif cmd_type == 'start_screen_stream':
                    if not STREAMING_CAPABLE:
                        response = {"status": "error", "message": "Streaming missing."}
                    else:
                        with self.video_streams_lock:
                            if addr in self.video_streams:
                                response = {"status": "error", "message": "Already streaming."}
                            else:
                                self.video_streams[addr] = {'status': 'init'}

                        if response is None:
                            try:
                                v_sock_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                v_sock_srv.bind((self.HOST, 0))
                                v_sock_srv.listen(1)
                                v_port = v_sock_srv.getsockname()[1]

                                NetworkProtocol.send_success(conn, "Port opened.", video_port=v_port)

                                v_sock_srv.settimeout(20.0)
                                v_client, _ = v_sock_srv.accept()
                                v_sock_srv.settimeout(None)
                                v_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                                stop_ev = threading.Event()
                                t = threading.Thread(target=self.stream_screen_to_client, args=(v_client, addr, stop_ev), daemon=True)
                                with self.video_streams_lock:
                                    self.video_streams[addr] = {'thread': t, 'stop_event': stop_ev, 'sock': v_client, 'srv_sock': v_sock_srv}
                                t.start()
                                continue
                            except Exception as e:
                                response = {"status": "error", "message": str(e)}
                                with self.video_streams_lock:
                                    self.video_streams.pop(addr, None)
                                if v_sock_srv: v_sock_srv.close()

                elif cmd_type == 'stop_screen_stream':
                    with self.video_streams_lock:
                        if addr in self.video_streams:
                            si = self.video_streams.pop(addr)
                            si['stop_event'].set()
                            try: si['srv_sock'].close()
                            except: pass
                            response = {"status": "ok", "message": "Stopped."}
                        else:
                            response = {"status": "error", "message": "No stream."}
                else:
                    response = {"status": "error", "message": "Unknown cmd"}

                if response:
                    NetworkProtocol.send_json(conn, response)

        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            with self.video_streams_lock:
                if addr in self.video_streams:
                    si = self.video_streams.pop(addr)
                    si['stop_event'].set()
            conn.close()

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.HOST, self.CONTROL_PORT))
            self.server_socket.listen(5)
            print(f"[SERVER] Listening on {self.HOST}:{self.CONTROL_PORT}")
            while True:
                conn, addr = self.server_socket.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                t.start()
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            if self.server_socket: self.server_socket.close()

if __name__ == "__main__":
    srv = RemoteServer()
    srv.start()