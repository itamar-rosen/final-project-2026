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

        self.stream_active = True
        self.stream_mode = "Performance"
        self.current_scale = 0.5
        self.fps_target = 30
        self.lag_counter = 0

        self.video_stop_event = threading.Event()
        self.cmd_queue = queue.Queue()

        threading.Thread(target=self._stream_video, daemon=True).start()
        threading.Thread(target=self._process_commands, daemon=True).start()

    def _send_chunked(self, frame_type, x, y, w, h, crop, q_val, is_first_chunk=False):
        """Recursively slices an image into smaller grids until it safely fits under the 64KB protocol limit."""
        success, encoded = cv2.imencode('.webp', crop, [cv2.IMWRITE_WEBP_QUALITY, q_val])
        if success:
            # 45000 bytes is the absolute safety limit to prevent struct.pack crashes after encryption
            if len(encoded) < 45000:
                # Only the VERY first chunk of a keyframe gets the 'F' flag to wipe the viewer's canvas
                current_ftype = b'F' if is_first_chunk else frame_type
                meta = struct.pack("!cHHHH", current_ftype, x, y, w, h)
                try:
                    enc_payload = self.fernet.encrypt(meta + encoded.tobytes())
                    return self.app.safe_send(self.app.sec.wrap(self.app.username, 3, self.gid, enc_payload))
                except Exception as e:
                    print(f"Network Send Error: {e}")
                    return False

            # If the frame is STILL too massive, slice it vertically or horizontally and route it again!
            if w >= h and w > 10:
                w1 = w // 2
                res1 = self._send_chunked(frame_type, x, y, w1, h, crop[:, :w1], q_val, is_first_chunk)
                res2 = self._send_chunked(frame_type, x + w1, y, w - w1, h, crop[:, w1:], q_val, False)
                return res1 and res2
            elif h > 10:
                h1 = h // 2
                res1 = self._send_chunked(frame_type, x, y, w, h1, crop[:h1, :], q_val, is_first_chunk)
                res2 = self._send_chunked(frame_type, x, y + h1, w, h - h1, crop[h1:, :], q_val, False)
                return res1 and res2
        return False

    def _stream_video(self):
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            last_gray = None
            last_scale = self.current_scale

            while not self.video_stop_event.is_set():
                try:
                    if not self.stream_active or self.viewers_count == 0:
                        time.sleep(0.5)
                        last_gray = None
                        continue

                    start_t = time.time()

                    # Scale boundaries: Floor of 50%, Ceiling of 85%.
                    self.current_scale = max(0.5, min(0.85, self.current_scale))

                    if self.current_scale != last_scale:
                        last_gray = None
                        last_scale = self.current_scale

                    sct_img = sct.grab(monitor)
                    img = np.array(sct_img)[:, :, :3]
                    img = cv2.resize(img, (0, 0), fx=self.current_scale, fy=self.current_scale)
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

                    q_val = 80 if self.stream_mode == "Quality" else 50
                    is_keyframe = False

                    if last_gray is None:
                        is_keyframe = True
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

                    # Route the frame entirely through the spatial chunker!
                    f_type = b'F' if is_keyframe else b'V'
                    success = self._send_chunked(f_type, x, y, w, h, crop, q_val, is_first_chunk=is_keyframe)

                    # If a critical network error occurred during chunking, reset the keyframe
                    if not success:
                        last_gray = None

                    elapsed = time.time() - start_t

                    if self.stream_mode == "Performance":
                        if elapsed > 0.04:
                            self.lag_counter += 1
                            if self.lag_counter > 5:
                                self.current_scale -= 0.1
                                self.lag_counter = 0
                        elif elapsed < 0.025:
                            self.lag_counter -= 1
                            if self.lag_counter < -15:
                                self.current_scale += 0.1
                                self.lag_counter = 0
                        else:
                            self.lag_counter = 0

                    time.sleep(max(0, (1.0 / self.fps_target) - elapsed))

                except Exception as e:
                    print(f"Host Video Error (Recovering): {e}")
                    last_gray = None
                    time.sleep(0.5)

    def route_incoming(self, sender, p_type, payload):
        if p_type == 0:
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
                    action = cmd['data'].get('action')
                    x_pct, y_pct = cmd['data'].get('x'), cmd['data'].get('y')
                    button = cmd['data'].get('button')

                    # Convert incoming percentages to the Host's absolute screen size!
                    screen_w, screen_h = pyautogui.size()
                    abs_x = int(x_pct * screen_w)
                    abs_y = int(y_pct * screen_h)

                    if action == 'move':
                        pyautogui.moveTo(abs_x, abs_y, duration=0)
                    elif action == 'click':
                        pyautogui.click(x=abs_x, y=abs_y, button=button)

                elif cmd_type == 'keyboard_event':
                    action, key = cmd['data'].get('action'), cmd['data'].get('key_name')
                    try:  # Wrapped in a try/except to ignore unsupported Tkinter keys safely
                        if action == 'press':
                            pyautogui.keyDown(key)
                        elif action == 'release':
                            pyautogui.keyUp(key)
                    except ValueError:
                        pass
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

    def __init__(self, parent_window, host_username, rc_callback):
        self.root = ctk.CTkToplevel(parent_window)
        self.root.title(f"Live Stream: {host_username}")
        self.root.geometry("800x600")
        self.active = True

        self.rc_callback = rc_callback
        self.rc_active = False

        # FIX: Converted to a strict CustomTkinter label
        self.video_label = ctk.CTkLabel(self.root, text="")
        self.video_label.pack(fill="both", expand=True)

        self.last_img_w, self.last_img_h = 1, 1
        self.last_offset_x, self.last_offset_y = 0, 0

        self.video_label.bind("<Motion>", lambda e: self._mouse_cb(e, 'move'))
        self.video_label.bind("<Button-1>", lambda e: self._mouse_cb(e, 'click', 'left'))
        self.video_label.bind("<Button-3>", lambda e: self._mouse_cb(e, 'click', 'right'))
        self.root.bind("<KeyPress>", lambda e: self._key_cb(e, 'press'))
        self.root.bind("<KeyRelease>", lambda e: self._key_cb(e, 'release'))

        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _mouse_cb(self, event, action, button='left'):
        if not self.rc_active: return

        real_x = event.x - self.last_offset_x
        real_y = event.y - self.last_offset_y

        if 0 <= real_x <= self.last_img_w and 0 <= real_y <= self.last_img_h:
            pct_x = real_x / self.last_img_w
            pct_y = real_y / self.last_img_h
            self.rc_callback(
                {'type': 'mouse_event', 'data': {'action': action, 'x': pct_x, 'y': pct_y, 'button': button}})

    def _key_cb(self, event, action):
        if not self.rc_active: return
        key = event.keysym.lower()
        translations = {'return': 'enter', 'prior': 'pageup', 'next': 'pagedown', 'escape': 'esc', 'control_l': 'ctrl',
                        'control_r': 'ctrl', 'shift_l': 'shift', 'shift_r': 'shift'}
        key = translations.get(key, key)
        self.rc_callback({'type': 'keyboard_event', 'data': {'action': action, 'key_name': key}})

    def update_frame(self, pil_img):
        try:
            if not self.active: return

            win_w = max(100, self.root.winfo_width())
            win_h = max(100, self.root.winfo_height())

            img_w, img_h = pil_img.size
            ratio = min(win_w / img_w, win_h / img_h)
            new_size = (int(img_w * ratio), int(img_h * ratio))

            resized_img = pil_img.resize(new_size, Image.Resampling.LANCZOS)

            self.last_img_w, self.last_img_h = new_size[0], new_size[1]

            label_w = self.video_label.winfo_width()
            label_h = self.video_label.winfo_height()
            self.last_offset_x = (label_w - self.last_img_w) // 2
            self.last_offset_y = (label_h - self.last_img_h) // 2

            # FIX: Convert the PIL image securely into CustomTkinter's native format
            img_ctk = ctk.CTkImage(light_image=resized_img, size=new_size)
            self.video_label.configure(image=img_ctk)

        except:
            pass

    def close(self):
        self.active = False
        self.root.destroy()

class HostHubWindow:
    """The dedicated Control Hub for the user sharing their screen"""

    def __init__(self, app, host_engine):
        self.app = app
        self.engine = host_engine
        self.connected_users = []  # NEW: Tracker for who is in the room

        self.root = ctk.CTkToplevel(app.root)
        self.root.title(f"Host Hub: {app.username}'s Room")
        self.root.geometry("400x500")  # Expanded slightly to fit the user list
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        ctk.CTkLabel(self.root, text="You are Broadcasting!", font=("Helvetica", 16, "bold")).pack(pady=10)

        # Invite Section
        self.invite_frame = ctk.CTkFrame(self.root)
        self.invite_frame.pack(fill="x", padx=20, pady=5)
        self.e_invite_target = ctk.CTkEntry(self.invite_frame, placeholder_text="Target Username")
        self.e_invite_target.pack(pady=5)
        ctk.CTkButton(self.invite_frame, text="Send Invite", command=self.send_invite).pack(pady=5)

        # Stream Controls
        self.btn_toggle_stream = ctk.CTkButton(self.root, text="Pause Screen Share", command=self.toggle_stream,
                                               fg_color="#8B0000", hover_color="#5c0000")
        self.btn_toggle_stream.pack(pady=5)

        self.mode_var = ctk.StringVar(value="Performance (High FPS)")
        self.mode_menu = ctk.CTkOptionMenu(self.root, values=["Performance (High FPS)", "Quality (Still / High Res)"],
                                           variable=self.mode_var, command=self.change_stream_mode)
        self.mode_menu.pack(pady=5)

        # --- NEW: User Management Section ---
        ctk.CTkLabel(self.root, text="Connected Viewers", font=("Helvetica", 12, "bold")).pack(pady=(10, 0))
        self.list_viewers = tk.Listbox(self.root, bg="#2b2b2b", fg="white", highlightthickness=0, height=5)
        self.list_viewers.pack(fill="x", padx=20, pady=5)

        self.btn_kick = ctk.CTkButton(self.root, text="Kick Selected Viewer", command=self.kick_user,
                                      fg_color="#cf3c3c", hover_color="#8f2727")
        self.btn_kick.pack(pady=5)

        # --- NEW: Disband Room Button ---
        self.btn_disband = ctk.CTkButton(self.root, text="Disband Room", command=self.close, fg_color="#8B0000",
                                         hover_color="#5c0000")
        self.btn_disband.pack(pady=15)
        # --- NEW: Host Security Toggle ---
        self.btn_allow_rc = ctk.CTkButton(self.root, text="Allow Remote Control: OFF", command=self.toggle_rc,
                                          fg_color="#8B0000", hover_color="#5c0000")
        self.btn_allow_rc.pack(pady=10)

    # Add this function anywhere inside the HostHubWindow class
    def toggle_rc(self):
        self.engine.allow_remote_control = not self.engine.allow_remote_control
        if self.engine.allow_remote_control:
            self.btn_allow_rc.configure(text="Allow Remote Control: ON", fg_color="#006400", hover_color="#004d00")
        else:
            self.btn_allow_rc.configure(text="Allow Remote Control: OFF", fg_color="#8B0000", hover_color="#5c0000")

    def add_user(self, username):
        if username not in self.connected_users:
            self.connected_users.append(username)
            self.list_viewers.insert("end", username)
            self.engine.viewers_count = len(self.connected_users)

    def remove_user(self, username):
        if username in self.connected_users:
            idx = self.connected_users.index(username)
            self.list_viewers.delete(idx)
            self.connected_users.remove(username)
            self.engine.viewers_count = len(self.connected_users)

    def kick_user(self):
        sel = self.list_viewers.curselection()
        if not sel: return
        target = self.connected_users[sel[0]]

        # Signal the viewer to close their app
        payload = json.dumps({"t": "KICK", "room": self.engine.gid})
        self.app.safe_send(self.app.sec.wrap(self.app.username, 2, target, payload.encode()))

        self.remove_user(target)

    def send_invite(self):
        target = self.e_invite_target.get()
        if not target: return
        payload = json.dumps({"t": "INVITE_OFFER", "room": self.engine.gid})
        self.app.safe_send(self.app.sec.wrap(self.app.username, 2, target, payload.encode()))
        messagebox.showinfo("Sent", f"Invite sent to {target}!")
        self.e_invite_target.delete(0, 'end')

    def toggle_stream(self):
        self.engine.stream_active = not self.engine.stream_active
        self.btn_toggle_stream.configure(
            text="Pause Screen Share" if self.engine.stream_active else "Resume Screen Share",
            fg_color="#8B0000" if self.engine.stream_active else "#006400")

    def change_stream_mode(self, choice):
        if "Quality" in choice:
            self.engine.stream_mode = "Quality"
            self.engine.current_scale = 0.85
            self.engine.fps_target = 10
        else:
            self.engine.stream_mode = "Performance"
            self.engine.fps_target = 30

    def close(self):
        # Disband: Tell every connected viewer the room is shutting down
        for user in self.connected_users:
            payload = json.dumps({"t": "DISBAND", "room": self.engine.gid})
            self.app.safe_send(self.app.sec.wrap(self.app.username, 2, user, payload.encode()))

        self.engine.stop()
        self.app.host_engine = None
        self.app.host_hub = None
        self.app.btn_create_room.configure(state="normal", text="Create Room & Share Screen")
        self.root.destroy()


class ViewerSessionWindow:
    """The Shortcut Hub window that manages the background processing"""

    def __init__(self, app, host_username, gid, aes_key):
        self.app = app
        self.host_username = host_username
        self.gid = gid
        self.fernet = Fernet(aes_key)
        self.active = True

        self.video_queue = queue.Queue(maxsize=10)
        self.current_frame = None  # NEW: The "pedestal" for the latest frame

        # Setup the Control Hub Window
        self.root = ctk.CTkToplevel(app.root)
        self.root.title(f"Hub: {host_username}")
        self.root.geometry("400x250")
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        ctk.CTkLabel(self.root, text=f"Connected to {host_username}", font=("Helvetica", 16, "bold")).pack(pady=15)

        # Wire up the button!
        self.rc_active = False
        self.rc_btn = ctk.CTkButton(self.root, text="Toggle Remote Control", command=self.toggle_rc)
        self.rc_btn.pack(pady=10)

        self.file_btn = ctk.CTkButton(self.root, text="Open File Explorer", state="disabled")
        self.file_btn.pack(pady=10)

        # Pass our secure network sender down into the Video window
        self.stream_window = VideoStreamWindow(self.root, self.host_username, self.send_rc_command)

        # --- NEW: Leave Room Button
        self.leave_btn = ctk.CTkButton(self.root, text="Leave Room", command=self.close, fg_color="#cf3c3c",
                                       hover_color="#8f2727")
        self.leave_btn.pack(pady=25)

        # Fire up the background frame processor
        threading.Thread(target=self._video_loop, daemon=True).start()

        # NEW: Start the dedicated, perfectly paced UI rendering loop
        self.root.after(33, self._render_ui_loop)

    def toggle_rc(self):
        self.rc_active = not self.rc_active
        self.stream_window.rc_active = self.rc_active  # Tell the video screen to start listening
        if self.rc_active:
            self.rc_btn.configure(text="Remote Control: ON", fg_color="#006400", hover_color="#004d00")
        else:
            self.rc_btn.configure(text="Toggle Remote Control", fg_color=['#3a7ebf', '#1f538d'])

    def send_rc_command(self, cmd_dict):
        """Encrypts and fires the input commands instantly to the Room"""
        if self.rc_active and self.app.relay_sock:
            try:
                payload = json.dumps({"t": "MSG", "m": self.fernet.encrypt(json.dumps(cmd_dict).encode()).decode()})
                self.app.safe_send(self.app.sec.wrap(self.app.username, 0, self.gid, payload.encode()))
            except Exception as e:
                print(f"RC Network Error: {e}")

    def route_incoming(self, sender, p_type, payload):
        if p_type == 3:
            try:
                dec = self.fernet.decrypt(payload)
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

    def _render_ui_loop(self):
        """Safely pulls the latest frame from the pedestal and draws it (~30 FPS max)"""
        if not self.active: return

        if self.current_frame is not None and self.stream_window.active:
            frame_to_draw = self.current_frame
            self.current_frame = None  # Clear the pedestal so we don't redraw the exact same image
            self.stream_window.update_frame(frame_to_draw)

        # Schedule the next check in 33 milliseconds
        self.root.after(33, self._render_ui_loop)

    def _video_loop(self):
        canvas = None
        while self.active:
            try:
                f_type, x, y, w, h, webp_bytes = self.video_queue.get(timeout=1.0)
                crop = cv2.imdecode(np.frombuffer(webp_bytes, np.uint8), cv2.IMREAD_COLOR)

                if crop is not None:
                    if crop.shape[0] != h or crop.shape[1] != w or h == 0 or w == 0:
                        continue

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

                    # NEW: Just place the image on the pedestal! No more forcing the UI to draw.
                    if self.active:
                        self.current_frame = pil_img

            except queue.Empty:
                pass
            except Exception as e:
                print(f"Viewer Processing Error: {e}")
                break

    def force_close(self, reason):
        """Called remotely by the Host when kicking or disbanding."""
        msg = "The host closed the room." if reason == 'DISBAND' else "You were kicked by the host."
        messagebox.showinfo("Disconnected", msg)
        self.close(send_leave=False)

    def close(self, send_leave=True):
        """Cleans up the UI and gracefully tells the Host we are leaving."""
        self.active = False

        # Send a LEAVE packet to the host if we closed the window ourselves
        if send_leave and self.app.relay_sock:
            payload = json.dumps({"t": "LEAVE", "room": self.gid})
            self.app.safe_send(self.app.sec.wrap(self.app.username, 2, self.host_username, payload.encode()))

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

        # --- NEW: Quit Button ---
        self.btn_quit = ctk.CTkButton(self.login_frame, text="Quit Application", command=self.root.destroy,
                                      fg_color="#cf3c3c", hover_color="#8f2727")
        self.btn_quit.pack(pady=5)

        self.lbl_status = ctk.CTkLabel(self.login_frame, text="")
        self.lbl_status.pack(pady=5)

    def _build_dashboard_ui(self):
        self.login_frame.destroy()
        self.dash_frame = ctk.CTkFrame(self.root)
        self.dash_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.dash_frame.grid_columnconfigure(0, weight=1)
        self.dash_frame.grid_columnconfigure(1, weight=1)
        self.dash_frame.grid_rowconfigure(1, weight=1)

        lbl = ctk.CTkLabel(self.dash_frame, text=f"Logged in as: {self.username}", font=("Helvetica", 16, "bold"))
        lbl.grid(row=0, column=0, columnspan=2, pady=10)

        # Host Panel (Simplified Lobby)
        self.host_panel = ctk.CTkFrame(self.dash_frame)
        self.host_panel.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(self.host_panel, text="My Room (Host)", font=("Helvetica", 14, "bold")).pack(pady=10)

        self.btn_create_room = ctk.CTkButton(self.host_panel, text="Create Room & Share Screen",
                                             command=self.create_room)
        self.btn_create_room.pack(pady=20)

        ctk.CTkLabel(self.host_panel, text="All controls will move\nto the Host Hub.", font=("Helvetica", 12),
                     text_color="gray").pack()

        # Viewer Panel (Lobby)
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

    def create_room(self):
        self.hosted_aes_key = Fernet.generate_key()
        self.hosted_gid = f"Room_{self.username}"
        self.safe_send(self.sec.wrap(self.username, 1, self.hosted_gid, json.dumps({'a': 'CREATE'}).encode()))

        self.host_engine = HostEngine(self, self.hosted_gid, self.hosted_aes_key)
        self.btn_create_room.configure(state="disabled", text="Room Created")

        # Spawn the dedicated Host Hub popup!
        self.host_hub = HostHubWindow(self, self.host_engine)

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

    def _handle_duplicate_username(self):
        """Tears down the dashboard and resets to the login screen if the name is taken"""
        messagebox.showerror("Connection Denied", "That username is currently in use!\nPlease choose a unique one.")
        if hasattr(self, 'dash_frame') and self.dash_frame.winfo_exists():
            self.dash_frame.destroy()

        self.username = None
        self._build_login_ui()
        self.lbl_status.configure(text="Error: Username taken.", text_color="red")
        self.btn_connect.configure(state="normal")

    def _central_router_loop(self):
        """The core traffic controller. Routes all packets to the correct UI/Background thread."""
        while True:
            try:
                sender, p_type, gid, payload = self.sec.receive(self.relay_sock)
                if not sender: break

                # --- NEW: Catch the duplicate username rejection! ---
                if p_type == 1 and gid == "ERR" and payload == b"TAKEN":
                    self.root.after(0, self._handle_duplicate_username)
                    break

                if p_type == 2:
                    data = json.loads(payload.decode())

                    if data.get('t') == 'INVITE_OFFER':
                        invite = {'host': sender, 'room': data['room']}
                        self.pending_invites.append(invite)
                        self.root.after(0, lambda h=sender: self.list_invites.insert("end", f"Invite from {h}"))

                    # 2. We are the host, and someone accepted our invite

                    elif data.get('t') == 'REQ' and self.host_engine:
                        viewer_pub = data['pub']
                        enc_aes = base64.b64encode(self.sec.rsa_encrypt(viewer_pub, self.hosted_aes_key)).decode()
                        reply = json.dumps({"t": "INV", "room": self.hosted_gid, "k": enc_aes})
                        self.safe_send(self.sec.wrap(self.username, 2, sender, reply.encode()))

                        # NEW: Add them to the Host UI list!
                        if hasattr(self, 'host_hub') and self.host_hub:
                            self.root.after(0, self.host_hub.add_user, sender)

                    elif data.get('t') == 'INV':
                        room = data['room']
                        aes_key = self.sec.rsa_decrypt(self.priv, base64.b64decode(data['k']))
                        self.safe_send(self.sec.wrap(self.username, 1, room, json.dumps({'a': 'JOIN'}).encode()))
                        self.root.after(0, lambda s=sender, r=room, k=aes_key: self._launch_viewer(s, r, k))

                        # --- NEW: Lifecycle Handlers ---

                    elif data.get('t') == 'KICK' or data.get('t') == 'DISBAND':
                        room = data['room']
                        if room in self.viewers:
                            # Forcefully close the viewer window on the UI thread
                            self.root.after(0, self.viewers[room].force_close, data.get('t'))

                    elif data.get('t') == 'LEAVE' and self.host_engine:
                        # A viewer voluntarily closed their window, remove them from the Host Hub!
                        if hasattr(self, 'host_hub') and self.host_hub:
                            self.root.after(0, self.host_hub.remove_user, sender)

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
        # 1. Signal the relay to free up our unique username!
        if app.relay_sock:
            app.safe_send(app.sec.wrap(app.username, 1, "REG", json.dumps({'a': 'QUIT'}).encode()))

        # 2. If we are hosting, disband the group and kick everyone out
        if hasattr(app, 'host_hub') and app.host_hub:
            app.host_hub.close()

        # 3. If we are viewing anyone, respectfully send them a LEAVE signal
        for v in list(app.viewers.values()):
            v.close(send_leave=True)

        root.destroy()


    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()