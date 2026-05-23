import os, time, threading, queue, json, struct, base64, socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk

# Video & Input Dependencies
import cv2
import numpy as np
import mss
import pyautogui
from pynput import mouse, keyboard
from cryptography.fernet import Fernet

# Protocol Dependencies
from protocol import SecurityEngine

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")
pyautogui.PAUSE = 0
pyautogui.FAILSAFE = False


class HostEngine:
    """Handles Screen Capture, Delta Frames, WebP Encoding, and Remote Commands"""

    def __init__(self, app, gid, aes_key):
        self.app = app
        self.gid = gid
        self.aes_key = aes_key
        self.fernet = Fernet(self.aes_key)
        self.active = True
        self.allow_remote_control = False
        self.viewers_count = 0

        # --- NEW: Dynamic Stream Settings ---
        self.stream_active = True
        self.stream_mode = "Performance"
        self.current_scale = 0.5
        self.fps_target = 30
        self.lag_counter = 0

        self.video_stop_event = threading.Event()
        self.cmd_queue = queue.Queue()

        threading.Thread(target=self._stream_video, daemon=True).start()
        threading.Thread(target=self._process_commands, daemon=True).start()

    def _stream_video(self):
        try:
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                last_gray = None
                last_scale = self.current_scale

                while not self.video_stop_event.is_set():
                    # Handle Pausing the Stream
                    if not self.stream_active or self.viewers_count == 0:
                        time.sleep(0.5)
                        last_gray = None  # Forces a fresh Keyframe when resumed
                        continue

                    start_t = time.time()

                    # Ensure current_scale is within safe bounds
                    self.current_scale = max(0.2, min(1.0, self.current_scale))

                    # If resolution changed, force a Keyframe reset
                    if self.current_scale != last_scale:
                        last_gray = None
                        last_scale = self.current_scale

                    sct_img = sct.grab(monitor)
                    img = np.array(sct_img)[:, :, :3]
                    img = cv2.resize(img, (0, 0), fx=self.current_scale, fy=self.current_scale)
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

                    frame_type = b'V'  # V for Video Delta (P-Frame)

                    if last_gray is None:
                        frame_type = b'F'  # F for Full Keyframe (I-Frame)
                        x, y, w, h = 0, 0, img.shape[1], img.shape[0]
                        crop = img
                        last_gray = gray
                    else:
                        diff = cv2.absdiff(last_gray, gray)
                        _, thresh = cv2.threshold(diff, 15, 255, cv2.THRESH_BINARY)
                        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

                        if not contours:
                            time.sleep(1.0 / self.fps_target)
                            continue

                        x_min, y_min = img.shape[1], img.shape[0]
                        x_max, y_max = 0, 0
                        for c in contours:
                            cx, cy, cw, ch = cv2.boundingRect(c)
                            x_min, y_min = min(x_min, cx), min(y_min, cy)
                            x_max, y_max = max(x_max, cx + cw), max(y_max, cy + ch)

                        x, y, w, h = x_min, y_min, x_max - x_min, y_max - y_min

                        if w <= 5 or h <= 5:
                            time.sleep(1.0 / self.fps_target)
                            continue

                        crop = img[y:y + h, x:x + w]
                        if crop.size == 0 or crop.shape[0] == 0 or crop.shape[1] == 0:
                            time.sleep(1.0 / self.fps_target)
                            continue

                        last_gray = gray

                    success, encoded = cv2.imencode('.webp', crop, [cv2.IMWRITE_WEBP_QUALITY, 50])
                    if success:
                        # Pack using frame_type to tell the viewer if it's a Delta or a Keyframe
                        meta = struct.pack("!cHHHH", frame_type, x, y, w, h)
                        enc_payload = self.fernet.encrypt(meta + encoded.tobytes())
                        if not self.app.safe_send(self.app.sec.wrap(self.app.username, 3, self.gid, enc_payload)):
                            self.stop()
                            break

                    elapsed = time.time() - start_t

                    # --- DYNAMIC RESOLUTION ALGORITHM ---
                    if self.stream_mode == "Performance":
                        if elapsed > 0.04:  # Running slow! CPU or Network is lagging
                            self.lag_counter += 1
                            if self.lag_counter > 5:
                                self.current_scale -= 0.1  # Shrink screen size
                                self.lag_counter = 0
                        elif elapsed < 0.025:  # Running fast!
                            self.lag_counter -= 1
                            if self.lag_counter < -15:
                                self.current_scale += 0.1  # Increase screen size
                                self.lag_counter = 0
                        else:
                            self.lag_counter = 0  # Stable

                    time.sleep(max(0, (1.0 / self.fps_target) - elapsed))
        except Exception as e:
            print(f"Host Video Error: {e}")

    def route_incoming(self, sender, p_type, payload):
        if p_type == 0:  # JSON Command
            try:
                data = json.loads(payload.decode())
                if data.get('t') == 'MSG':
                    cmd = json.loads(self.fernet.decrypt(data['m'].encode()).decode())
                    self.cmd_queue.put((sender, cmd))
            except:
                pass


    def _process_commands(self):
        while self.active:
            try:
                sender, cmd = self.cmd_queue.get(timeout=1.0)
                if not self.allow_remote_control: continue

                cmd_type = cmd.get('type')
                if cmd_type == 'mouse_event':
                    action, x, y = cmd['data'].get('action'), cmd['data'].get('x'), cmd['data'].get('y')
                    button = cmd['data'].get('button')
                    # Coordinate scaling reverse
                    x, y = int(x / 0.5), int(y / 0.5)
                    if action == 'move':
                        pyautogui.moveTo(x, y, duration=0)
                    elif action == 'click':
                        pyautogui.click(x=x, y=y, button=button)
                elif cmd_type == 'keyboard_event':
                    action, key = cmd['data'].get('action'), cmd['data'].get('key_name')
                    if action == 'press':
                        pyautogui.keyDown(key)
                    elif action == 'release':
                        pyautogui.keyUp(key)
            except queue.Empty:
                pass
            except Exception as e:
                print(f"Host Command Error: {e}")

    def stop(self):
        self.active = False
        self.video_stop_event.set()


from PIL import Image, ImageTk


class VideoStreamWindow:
    """The dedicated, independent window solely for the live video feed"""
    def __init__(self, parent_window, host_username):
        self.root = ctk.CTkToplevel(parent_window)
        self.root.title(f"Live Stream: {host_username}")
        self.root.geometry("800x600")
        self.active = True

        # Pure video canvas filling the window
        self.video_label = tk.Label(self.root, bg="#000000")
        self.video_label.pack(fill="both", expand=True)

        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def update_frame(self, pil_img):
        try:
            if not self.active: return

            # Get the exact current size of the user's window
            win_w = max(100, self.root.winfo_width())
            win_h = max(100, self.root.winfo_height())

            # Calculate the aspect ratio to perfectly fit the window
            img_w, img_h = pil_img.size
            ratio = min(win_w / img_w, win_h / img_h)
            new_size = (int(img_w * ratio), int(img_h * ratio))

            # Use .resize() instead of .thumbnail() so it can scale UP to full screen
            resized_img = pil_img.resize(new_size, Image.Resampling.LANCZOS)

            img_tk = ImageTk.PhotoImage(image=resized_img)
            self.video_label.configure(image=img_tk)
            self.video_label.image = img_tk
        except: pass

    def close(self):
        self.active = False
        self.root.destroy()


class ViewerSessionWindow:
    """The Shortcut Hub window (The one you see now) that manages the background processing"""

    def __init__(self, app, host_username, gid, aes_key):
        self.app = app
        self.host_username = host_username
        self.gid = gid
        self.fernet = Fernet(aes_key)
        self.active = True

        self.video_queue = queue.Queue(maxsize=10)
        self.stream_window = None  # Will hold the separate video frame

        #Setup the Control Hub Window
        self.root = ctk.CTkToplevel(app.root)
        self.root.title(f"Hub: {host_username}")
        self.root.geometry("400x250")
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        ctk.CTkLabel(self.root, text=f"Connected to {host_username}", font=("Helvetica", 16, "bold")).pack(pady=15)

        # Feature Buttons Space (Your future feature shortcuts go here!)
        self.rc_btn = ctk.CTkButton(self.root, text="Toggle Remote Control", state="disabled")
        self.rc_btn.pack(pady=10)

        self.file_btn = ctk.CTkButton(self.root, text="Open File Explorer (Future Feature)", state="disabled")
        self.file_btn.pack(pady=10)

        # Fire up the background frame processor
        threading.Thread(target=self._video_loop, daemon=True).start()

    def route_incoming(self, sender, p_type, payload):
        if p_type == 3:
            try:
                dec = self.fernet.decrypt(payload)
                # Now accepts BOTH 'V' (Delta) and 'F' (Full Frame)
                if dec.startswith(b'V') or dec.startswith(b'F'):
                    f_type, x, y, w, h = struct.unpack("!cHHHH", dec[:9])
                    if self.video_queue.qsize() > 5:
                        try:
                            self.video_queue.get_nowait()
                        except:
                            pass
                    self.video_queue.put((f_type, x, y, w, h, dec[9:]))
            except:
                pass

    def _video_loop(self):
        canvas = None

        while self.active:
            try:
                f_type, x, y, w, h, webp_bytes = self.video_queue.get(timeout=1.0)
                crop = cv2.imdecode(np.frombuffer(webp_bytes, np.uint8), cv2.IMREAD_COLOR)

                if crop is not None:
                    if crop.shape[0] != h or crop.shape[1] != w or h == 0 or w == 0:
                        continue

                        # KEYFRAME DETECTED: The host changed resolution!
                    # Instantly wipe the canvas and resize it to the new dynamic layout.
                    if f_type == b'F':
                        canvas = np.zeros((h, w, 3), dtype=np.uint8)

                    if canvas is None:
                        canvas = np.zeros((max(h, y + h), max(w, x + w), 3), dtype=np.uint8)

                    if y + h > canvas.shape[0] or x + w > canvas.shape[1] or canvas.size == 0:
                        new_h = max(canvas.shape[0], y + h)
                        new_w = max(canvas.shape[1], x + w)
                        new_canvas = np.zeros((new_h, new_w, 3), dtype=np.uint8)
                        new_canvas[0:canvas.shape[0], 0:canvas.shape[1]] = canvas
                        canvas = new_canvas

                    try:
                        canvas[y:y + h, x:x + w] = crop
                    except ValueError:
                        continue

                    rgb_image = cv2.cvtColor(canvas, cv2.COLOR_BGR2RGB)
                    pil_img = Image.fromarray(rgb_image)

                    if self.active:
                        self.root.after(0, self._render_to_separate_window, pil_img)

            except queue.Empty:
                pass
            except Exception as e:
                print(f"Viewer Processing Error: {e}")
                break

    def _render_to_separate_window(self, pil_img):
        """Ensures the separate video window exists and pushes the image frame onto it"""
        if not self.active: return

        # If the video window doesn't exist yet, or was closed, spawn it safely on the main thread
        if self.stream_window is None or not self.stream_window.active:
            self.stream_window = VideoStreamWindow(self.root, self.host_username)

        self.stream_window.update_frame(pil_img)

    def close(self):
        self.active = False
        if self.stream_window and self.stream_window.active:
            self.stream_window.close()
        if self.gid in self.app.viewers:
            del self.app.viewers[self.gid]
        self.root.destroy()


class UnifiedApp:
    """The Main Central Router and Dashboard UI"""

    def __init__(self, root):
        self.root = root
        self.root.title("P2P Unified Node")
        self.root.geometry("600x500")

        self.sec = SecurityEngine()
        self.priv, self.pub = self.sec.generate_rsa_keys()
        self.relay_sock = None
        self.username = None

        self.host_engine = None
        self.hosted_gid = None
        self.hosted_aes_key = None

        self.viewers = {}  # gid: ViewerSessionWindow
        self.pending_invites = []
        self.send_lock = threading.Lock()
        self._build_login_ui()

    # --- NEW: Safe Network Sender ---

    def safe_send(self, packet):
        with self.send_lock:
            try:
                self.relay_sock.sendall(packet)
                return True
            except Exception as e:
                return False

    # --- UI Builders ---
    def _build_login_ui(self):
        self.login_frame = ctk.CTkFrame(self.root)
        self.login_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(self.login_frame, text="Join the P2P Network", font=("Helvetica", 20, "bold")).pack(pady=30)
        self.e_join_code = ctk.CTkEntry(self.login_frame, placeholder_text="Join Code (from relay)", width=300)
        self.e_join_code.pack(pady=10)
        self.e_username = ctk.CTkEntry(self.login_frame, placeholder_text="Your Username", width=300)
        self.e_username.pack(pady=10)

        self.btn_connect = ctk.CTkButton(self.login_frame, text="Connect", command=self.connect_to_relay)
        self.btn_connect.pack(pady=20)
        self.lbl_status = ctk.CTkLabel(self.login_frame, text="")
        self.lbl_status.pack(pady=5)

    def _build_dashboard_ui(self):
        self.login_frame.destroy()
        self.dash_frame = ctk.CTkFrame(self.root)
        self.dash_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Grid Layout Configuration
        self.dash_frame.grid_columnconfigure(0, weight=1)
        self.dash_frame.grid_columnconfigure(1, weight=1)
        self.dash_frame.grid_rowconfigure(1, weight=1)

        # FIX: Use .grid() instead of .pack() for the title label!
        lbl = ctk.CTkLabel(self.dash_frame, text=f"Logged in as: {self.username}", font=("Helvetica", 16, "bold"))
        lbl.grid(row=0, column=0, columnspan=2, pady=10)

        # Host Panel
        self.host_panel = ctk.CTkFrame(self.dash_frame)
        self.host_panel.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(self.host_panel, text="My Room (Host)", font=("Helvetica", 14, "bold")).pack(pady=10)

        self.btn_create_room = ctk.CTkButton(self.host_panel, text="Create Room & Share Screen",
                                             command=self.create_room)
        self.btn_create_room.pack(pady=10)

        # --- NEW: Host Stream Controls ---
        self.btn_toggle_stream = ctk.CTkButton(self.host_panel, text="Pause Screen Share", command=self.toggle_stream,
                                               state="disabled", fg_color="#8B0000", hover_color="#5c0000")
        self.btn_toggle_stream.pack(pady=5)

        self.mode_var = ctk.StringVar(value="Performance (High FPS)")
        self.mode_menu = ctk.CTkOptionMenu(self.host_panel,
                                           values=["Performance (High FPS)", "Quality (Still / High Res)"],
                                           variable=self.mode_var, command=self.change_stream_mode, state="disabled")
        self.mode_menu.pack(pady=10)

        self.invite_frame = ctk.CTkFrame(self.host_panel, fg_color="transparent")
        self.e_invite_target = ctk.CTkEntry(self.invite_frame, placeholder_text="Target Username")
        self.e_invite_target.pack(pady=5)
        ctk.CTkButton(self.invite_frame, text="Send Invite", command=self.send_invite).pack(pady=5)

        # Viewer Panel
        self.view_panel = ctk.CTkFrame(self.dash_frame)
        self.view_panel.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(self.view_panel, text="Pending Invites", font=("Helvetica", 14, "bold")).pack(pady=10)

        self.list_invites = tk.Listbox(self.view_panel, bg="#2b2b2b", fg="white", highlightthickness=0)
        self.list_invites.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkButton(self.view_panel, text="Accept Selected", command=self.accept_invite).pack(pady=10)

    # --- Network Logic ---
    def connect_to_relay(self):
        code, user = self.e_join_code.get(), self.e_username.get()
        if not code or not user: return
        self.btn_connect.configure(state="disabled")
        self.lbl_status.configure(text="Connecting...")
        threading.Thread(target=self._connect_thread, args=(code, user), daemon=True).start()

    def _connect_thread(self, join_code, username):
        try:
            self.relay_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if ":" in join_code:
                host, port = join_code.replace("tcp://", "").split(":")
            else:
                data = base64.urlsafe_b64decode(join_code + "==")
                reg_id, h_idx, port, salt = struct.unpack("!BBHH", data)
                regs = {0: 'us', 1: 'eu', 2: 'ap', 3: 'au', 4: 'sa', 5: 'jp', 6: 'in'}
                host = f"{h_idx}.tcp.{regs.get(reg_id, 'us')}.ngrok.io" if reg_id != 99 else f"{h_idx}.tcp.ngrok.io"

            self.relay_sock.connect((host, int(port)))
            self.relay_sock.sendall(self.sec.wrap(username, 1, "REG", json.dumps({'pub': self.pub}).encode()))

            self.username = username
            self.root.after(0, self._build_dashboard_ui)

            # Start the central multiplex router
            threading.Thread(target=self._central_router_loop, daemon=True).start()
        except Exception as e:
            self.root.after(0, lambda: [self.btn_connect.configure(state="normal"),
                                        self.lbl_status.configure(text=f"Error: {e}")])

    def toggle_stream(self):
        if self.host_engine:
            self.host_engine.stream_active = not self.host_engine.stream_active
            if self.host_engine.stream_active:
                self.btn_toggle_stream.configure(text="Pause Screen Share", fg_color="#8B0000")
            else:
                self.btn_toggle_stream.configure(text="Resume Screen Share", fg_color="#006400")

    def change_stream_mode(self, choice):
        if self.host_engine:
            if "Quality" in choice:
                self.host_engine.stream_mode = "Quality"
                self.host_engine.current_scale = 1.0  # Full Original Resolution
                self.host_engine.fps_target = 5  # Low FPS (Like a slide show)
            else:
                self.host_engine.stream_mode = "Performance"
                self.host_engine.fps_target = 30  # High FPS Video
                # The dynamic logic will automatically shrink the scale

    def create_room(self):
        self.hosted_aes_key = Fernet.generate_key()
        self.hosted_gid = f"Room_{self.username}"
        self.safe_send(self.sec.wrap(self.username, 1, self.hosted_gid, json.dumps({'a': 'CREATE'}).encode()))

        self.host_engine = HostEngine(self, self.hosted_gid, self.hosted_aes_key)
        self.btn_create_room.configure(state="disabled", text="Room Created (Broadcasting)")
        self.invite_frame.pack(fill="x", padx=10, pady=10)

    def send_invite(self):
        target = self.e_invite_target.get()
        if not target or not self.hosted_gid: return
        payload = json.dumps({"t": "INVITE_OFFER", "room": self.hosted_gid})
        self.safe_send(self.sec.wrap(self.username, 2, target, payload.encode()))
        messagebox.showinfo("Sent", f"Invite sent to {target}!")
        self.e_invite_target.delete(0, 'end')

    def accept_invite(self):
        sel = self.list_invites.curselection()
        if not sel: return
        idx = sel[0]
        invite = self.pending_invites[idx]

        payload = json.dumps({"t": "REQ", "room": invite['room'], "pub": self.pub})
        self.safe_send(self.sec.wrap(self.username, 2, invite['host'], payload.encode()))

        self.list_invites.delete(idx)
        del self.pending_invites[idx]

    def _central_router_loop(self):
        """The core traffic controller. Routes all packets to the correct UI/Background thread."""
        while True:
            try:
                sender, p_type, gid, payload = self.sec.receive(self.relay_sock)
                if not sender: break

                if p_type == 2:
                    data = json.loads(payload.decode())

                    if data.get('t') == 'INVITE_OFFER':
                        invite = {'host': sender, 'room': data['room']}
                        self.pending_invites.append(invite)
                        self.root.after(0, lambda h=sender: self.list_invites.insert("end", f"Invite from {h}"))

                    # 2. We are the host, and someone accepted our invite

                    # 2. We are the host, and someone accepted our invite

                        # 2. We are the host, and someone accepted our invite

                    elif data.get('t') == 'REQ' and self.host_engine:
                        viewer_pub = data['pub']  # Leave as String

                        # Leave hosted_aes_key as Bytes! This is the natively correct way.
                        enc_aes = base64.b64encode(self.sec.rsa_encrypt(viewer_pub, self.hosted_aes_key)).decode()

                        reply = json.dumps({"t": "INV", "room": self.hosted_gid, "k": enc_aes})
                        self.safe_send(self.sec.wrap(self.username, 2, sender, reply.encode()))

                        # Tell the HostEngine it is time to start broadcasting video!
                        self.host_engine.viewers_count += 1

                    elif data.get('t') == 'INV':
                        room = data['room']
                        aes_key = self.sec.rsa_decrypt(self.priv, base64.b64decode(data['k']))
                        self.safe_send(self.sec.wrap(self.username, 1, room, json.dumps({'a': 'JOIN'}).encode()))
                        self.root.after(0, lambda s=sender, r=room, k=aes_key: self._launch_viewer(s, r, k))

                elif gid == self.hosted_gid and self.host_engine:
                    self.host_engine.route_incoming(sender, p_type, payload)

                elif gid in self.viewers:
                    self.viewers[gid].route_incoming(sender, p_type, payload)

            # Catch errors safely
            except Exception as e:
                if isinstance(e, (ConnectionAbortedError, ConnectionResetError, OSError)):
                    print("Network socket closed cleanly.")
                    break

                print(f"Packet Processing Error (Ignored): {e}")
                continue  # DO NOT break the loop for a bad packet!

    def _launch_viewer(self, host, gid, aes_key):
        self.viewers[gid] = ViewerSessionWindow(self, host, gid, aes_key)


if __name__ == "__main__":
    root = ctk.CTk()
    app = UnifiedApp(root)


    def on_closing():
        if app.host_engine: app.host_engine.stop()
        for v in app.viewers.values(): v.close()
        root.destroy()


    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()