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
        self.active_controller = None  # Tracks the designated authenticated user granted remote access rights
        self.viewers_count = 0

        self.stream_active = True
        self.stream_mode = "Performance"
        self.current_scale = 0.5
        self.fps_target = 30
        self.lag_counter = 0

        self.video_stop_event = threading.Event()
        self.cmd_queue = queue.Queue()

        # Hardware-level mouse controller abstraction for low-overhead position tracking
        self.mouse_ctrl = mouse.Controller()

        threading.Thread(target=self._stream_video, daemon=True).start()
        threading.Thread(target=self._process_commands, daemon=True).start()

    def _send_chunked(self, frame_type, x, y, w, h, crop, q_val, is_first_chunk=False):
        """Recursively slices an image into smaller grids until it safely fits under the 64KB protocol limit."""
        success, encoded = cv2.imencode('.webp', crop, [cv2.IMWRITE_WEBP_QUALITY, q_val])
        if success:
            # 45000 bytes is the absolute safety limit to prevent struct.pack crashes after encryption
            if len(encoded) < 45000:
                # Assign keyframe reset flag exclusively to the initial chunk of a keyframe packet payload
                current_ftype = b'F' if is_first_chunk else frame_type
                meta = struct.pack("!cHHHH", current_ftype, x, y, w, h)
                try:
                    enc_payload = self.fernet.encrypt(meta + encoded.tobytes())
                    return self.app.safe_send(self.app.sec.wrap(self.app.username, 3, self.gid, enc_payload))
                except Exception as e:
                    print(f"Network Send Error: {e}")
                    return False

            # Divide out-of-bounds frames along spatial dimensions and clear recursively
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
                cmd_type = cmd.get('type')

                # Access validation checking: Authenticate incoming control events against the token holder
                if cmd_type in ['mouse_event', 'keyboard_event'] and sender != self.active_controller:
                    continue

                if cmd_type == 'mouse_event':
                    action = cmd['data'].get('action')
                    x_pct, y_pct = cmd['data'].get('x', 0), cmd['data'].get('y', 0)
                    button = cmd['data'].get('button', 'left')

                    screen_w, screen_h = pyautogui.size()
                    abs_x = int(x_pct * screen_w)
                    abs_y = int(y_pct * screen_h)

                    if action == 'move':
                        # Direct interaction execution via pynput to bypass alternative library processing overhead
                        self.mouse_ctrl.position = (abs_x, abs_y)
                    elif action == 'mousedown':
                        pyautogui.mouseDown(x=abs_x, y=abs_y, button=button)
                    elif action == 'mouseup':
                        pyautogui.mouseUp(x=abs_x, y=abs_y, button=button)
                    elif action == 'scroll':
                        amount = cmd['data'].get('amount', 0)
                        pyautogui.scroll(amount, x=abs_x, y=abs_y)


                elif cmd_type == 'keyboard_event':

                    action, key = cmd['data'].get('action'), cmd['data'].get('key_name')

                    try:

                        if action == 'press':

                            pyautogui.keyDown(key)

                        elif action == 'release':

                            pyautogui.keyUp(key)

                    except ValueError:

                        # Logging structural anomalies caught from interface input processing faults

                        print(f"PyAutoGUI doesn't understand this key: {key}")

                elif cmd_type == 'file_event':
                    action = cmd['data'].get('action')
                    path = cmd['data'].get('path')

                    if action == 'list_dir':
                        try:
                            if not path or path == "HOME":
                                path = os.path.expanduser('~')
                            elif path == "UP":
                                current = cmd['data'].get('current')
                                path = os.path.dirname(current)

                            items = os.listdir(path)
                            dirs = [{"name": d} for d in items if os.path.isdir(os.path.join(path, d))]
                            files = [{"name": f, "size": os.path.getsize(os.path.join(path, f))} for f in items if
                                     os.path.isfile(os.path.join(path, f))]

                            resp = {'type': 'dir_result', 'path': path, 'dirs': dirs, 'files': files}
                            enc_resp = self.fernet.encrypt(json.dumps(resp).encode()).decode()
                            self.app.safe_send(self.app.sec.wrap(self.app.username, 0, sender,
                                                                 json.dumps({"t": "MSG", "m": enc_resp}).encode()))
                        except Exception as e:
                            print(f"File Directory Error: {e}")

                    elif action == 'download':
                        try:
                            # Safely read and slice the file into 40KB chunks to bypass the network struct limits
                            with open(path, 'rb') as f:
                                file_data = f.read()

                            chunk_size = 40000
                            total_chunks = max(1, (len(file_data) + chunk_size - 1) // chunk_size)

                            for i in range(total_chunks):
                                chunk = file_data[i * chunk_size: (i + 1) * chunk_size]
                                b64_chunk = base64.b64encode(chunk).decode()

                                resp = {
                                    'type': 'file_chunk',
                                    'filename': os.path.basename(path),
                                    'chunk_idx': i,
                                    'total_chunks': total_chunks,
                                    'data': b64_chunk
                                }
                                enc_resp = self.fernet.encrypt(json.dumps(resp).encode()).decode()
                                self.app.safe_send(self.app.sec.wrap(self.app.username, 0, sender,
                                                                     json.dumps({"t": "MSG", "m": enc_resp}).encode()))

                                # Give the network socket a tiny breather between chunks so we don't flood the server
                                time.sleep(0.02)
                                # ... (your existing download logic) ...

                        except Exception as e:
                            print(f"File Download Error: {e}")
                    elif action == 'upload_chunk':
                        try:
                            target_dir = cmd['data'].get('target_dir')
                            filename = cmd['data'].get('filename')
                            chunk_idx = cmd['data'].get('chunk_idx')
                            b64_chunk = cmd['data'].get('chunk_data')

                            chunk_data = base64.b64decode(b64_chunk.encode())

                            # Use os.path.join so it perfectly formats the slashes for Windows/Mac/Linux
                            target_path = os.path.join(target_dir, filename)

                            # If it's the very first chunk, overwrite any existing file with the same name.
                            # Otherwise, append the bytes to the end of the file.
                            mode = 'wb' if chunk_idx == 0 else 'ab'
                            with open(target_path, mode) as f:
                                f.write(chunk_data)

                        except Exception as e:
                            print(f"File Upload Receiver Error: {e}")
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

        self.canvas = tk.Canvas(self.root, bg="#000000", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        self.last_img_w, self.last_img_h = 1, 1
        self.last_offset_x, self.last_offset_y = 0, 0
        self.last_move_time = 0

        self.canvas.bind("<Enter>", lambda e: self.canvas.focus_set())

        # Subsystem Bindings: Continuous dragging movement handlers
        self.canvas.bind("<Motion>", lambda e: self._mouse_cb(e, 'move'))
        self.canvas.bind("<B1-Motion>", lambda e: self._mouse_cb(e, 'move'))  # Left drag
        self.canvas.bind("<B3-Motion>", lambda e: self._mouse_cb(e, 'move'))  # Right drag

        # Subsystem Bindings: Discrete mouse click event parameters
        self.canvas.bind("<ButtonPress-1>", lambda e: [self.canvas.focus_set(), self._mouse_cb(e, 'mousedown', 'left')])
        self.canvas.bind("<ButtonRelease-1>", lambda e: self._mouse_cb(e, 'mouseup', 'left'))
        self.canvas.bind("<ButtonPress-3>",
                         lambda e: [self.canvas.focus_set(), self._mouse_cb(e, 'mousedown', 'right')])
        self.canvas.bind("<ButtonRelease-3>", lambda e: self._mouse_cb(e, 'mouseup', 'right'))

        # Subsystem Bindings: Multi-platform scroll mechanics coordination
        self.canvas.bind("<MouseWheel>", self._scroll_cb)  # Windows/Mac
        self.canvas.bind("<Button-4>", self._scroll_cb)  # Linux Scroll Up
        self.canvas.bind("<Button-5>", self._scroll_cb)  # Linux Scroll Down

        self.canvas.bind("<KeyPress>", lambda e: self._key_cb(e, 'press'))
        self.canvas.bind("<KeyRelease>", lambda e: self._key_cb(e, 'release'))

        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _scroll_cb(self, event):
        if not self.rc_active: return

        # Normalize scroll units across operating systems
        if hasattr(event, 'num') and event.num == 4:
            amount = 120
        elif hasattr(event, 'num') and event.num == 5:
            amount = -120
        else:
            amount = event.delta

        real_x = event.x - self.last_offset_x
        real_y = event.y - self.last_offset_y

        if 0 <= real_x <= self.last_img_w and 0 <= real_y <= self.last_img_h:
            pct_x = real_x / self.last_img_w
            pct_y = real_y / self.last_img_h
            self.rc_callback(
                {'type': 'mouse_event', 'data': {'action': 'scroll', 'x': pct_x, 'y': pct_y, 'amount': amount}})

    def _mouse_cb(self, event, action, button='left'):
        if not self.rc_active: return

        if action == 'move':
            now = time.time()
            # Core Performance Optimization: Enforces systematic cursor position polling tracking frequency
            if now - self.last_move_time < 0.015:
                return
            self.last_move_time = now

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

        translations = {
            'return': 'enter', 'prior': 'pageup', 'next': 'pagedown', 'escape': 'esc',
            'control_l': 'ctrl', 'control_r': 'ctrl', 'shift_l': 'shift', 'shift_r': 'shift',
            'alt_l': 'alt', 'alt_r': 'alt', 'period': '.', 'comma': ',', 'minus': '-',
            'plus': '+', 'equal': '=', 'space': 'space', 'backspace': 'backspace', 'tab': 'tab'
        }
        key = translations.get(key, key)
        self.rc_callback({'type': 'keyboard_event', 'data': {'action': action, 'key_name': key}})

    def update_frame(self, pil_img):
        try:
            if not self.active: return

            win_w = max(100, self.canvas.winfo_width())
            win_h = max(100, self.canvas.winfo_height())

            img_w, img_h = pil_img.size
            ratio = min(win_w / img_w, win_h / img_h)
            new_size = (int(img_w * ratio), int(img_h * ratio))

            resized_img = pil_img.resize(new_size, Image.Resampling.LANCZOS)

            self.last_img_w, self.last_img_h = new_size[0], new_size[1]
            self.last_offset_x = (win_w - self.last_img_w) // 2
            self.last_offset_y = (win_h - self.last_img_h) // 2

            img_tk = ImageTk.PhotoImage(image=resized_img)

            self.canvas.delete("all")
            self.canvas.create_image(win_w // 2, win_h // 2, image=img_tk, anchor="center")
            self.canvas.image = img_tk

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
        self.connected_users = []

        self.root = ctk.CTkToplevel(app.root)
        self.root.title(f"Host Hub: {app.username}'s Room")
        self.root.geometry("400x550")
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

        # Interface Setup: Active participant observation matrix
        ctk.CTkLabel(self.root, text="Connected Viewers", font=("Helvetica", 12, "bold")).pack(pady=(10, 0))
        self.list_viewers = tk.Listbox(self.root, bg="#2b2b2b", fg="white", highlightthickness=0, height=5)
        self.list_viewers.pack(fill="x", padx=20, pady=5)

        # Interaction Controls: Asynchronous input assignment authorization mechanism
        self.btn_grant_rc = ctk.CTkButton(self.root, text="Grant Control to Selected", command=self.toggle_user_control,
                                          fg_color="#3a7ebf")
        self.btn_grant_rc.pack(pady=5)

        self.btn_kick = ctk.CTkButton(self.root, text="Kick Selected Viewer", command=self.kick_user,
                                      fg_color="#cf3c3c", hover_color="#8f2727")
        self.btn_kick.pack(pady=5)

        self.btn_disband = ctk.CTkButton(self.root, text="Disband Room", command=self.close, fg_color="#8B0000",
                                         hover_color="#5c0000")
        self.btn_disband.pack(pady=15)

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

            # Execution Guardrail: Revoke command authority states if token holder suddenly terminates session
            if self.engine.active_controller == username:
                self.engine.active_controller = None
                self.btn_grant_rc.configure(text="Grant Control to Selected", fg_color="#3a7ebf", hover_color="#1f538d")

    # Cryptographic & Control State Routines: Token Tokenization and Context Swap Engine
    def toggle_user_control(self):
        # 1. If someone already has control, revoke it (ignoring who is currently highlighted in the list)
        if self.engine.active_controller:
            self.engine.active_controller = None
            self.btn_grant_rc.configure(text="Grant Control to Selected", fg_color="#3a7ebf", hover_color="#1f538d")
            return

        # 2. If nobody has control, check if a user is selected
        sel = self.list_viewers.curselection()
        if not sel:
            messagebox.showwarning("Notice", "Please select a viewer from the list first.")
            return

        # 3. Hand the token to the selected user!
        target = self.connected_users[sel[0]]
        self.engine.active_controller = target
        self.btn_grant_rc.configure(text=f"Revoke Control ({target})", fg_color="#006400", hover_color="#004d00")

    def kick_user(self):
        sel = self.list_viewers.curselection()
        if not sel: return
        target = self.connected_users[sel[0]]

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
        for user in self.connected_users:
            payload = json.dumps({"t": "DISBAND", "room": self.engine.gid})
            self.app.safe_send(self.app.sec.wrap(self.app.username, 2, user, payload.encode()))

        self.engine.stop()
        self.app.host_engine = None
        self.app.host_hub = None
        self.app.btn_create_room.configure(state="normal", text="Create Room & Share Screen")
        self.root.destroy()


class FileExplorerWindow:
    def __init__(self, parent_window, host_username, send_callback):
        self.root = ctk.CTkToplevel(parent_window)
        self.root.title(f"File Explorer: {host_username}")
        self.root.geometry("600x500")
        self.active = True
        self.send_callback = send_callback

        self.current_path = ""
        self.download_target = None

        # Top Bar: Navigation
        self.top_frame = ctk.CTkFrame(self.root)
        self.top_frame.pack(fill="x", padx=10, pady=10)

        self.btn_up = ctk.CTkButton(self.top_frame, text="↑ Up", width=60, command=self.go_up)
        self.btn_up.pack(side="left", padx=5)

        self.lbl_path = ctk.CTkLabel(self.top_frame, text="Requesting path...", font=("Helvetica", 12, "bold"))
        self.lbl_path.pack(side="left", padx=10, fill="x", expand=True)

        # Middle: The File List
        self.listbox = tk.Listbox(self.root, bg="#2b2b2b", fg="white", highlightthickness=0, font=("Courier", 11))
        self.listbox.pack(fill="both", expand=True, padx=10, pady=5)
        self.listbox.bind("<Double-Button-1>", self.on_double_click)

        # Bottom Bar: Actions
        self.bottom_frame = ctk.CTkFrame(self.root)
        self.bottom_frame.pack(fill="x", padx=10, pady=10)

        self.btn_refresh = ctk.CTkButton(self.bottom_frame, text="Refresh", width=80,
                                         command=lambda: self.request_dir(self.current_path))
        self.btn_refresh.pack(side="left", padx=5)

        self.btn_download = ctk.CTkButton(self.bottom_frame, text="Download Selected", width=140,
                                          command=self.download_file, fg_color="#3a7ebf")
        self.btn_download.pack(side="left", padx=5)

        # Interface Setup: Directory layout upload trigger initialization
        self.btn_upload = ctk.CTkButton(self.bottom_frame, text="Upload File Here", width=140, command=self.upload_file,
                                        fg_color="#2b8c4c", hover_color="#1c5e33")
        self.btn_upload.pack(side="right", padx=5)

        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.request_dir("HOME")

    def request_dir(self, path):
        self.send_callback({'type': 'file_event', 'data': {'action': 'list_dir', 'path': path}})

    def go_up(self):
        self.send_callback(
            {'type': 'file_event', 'data': {'action': 'list_dir', 'path': 'UP', 'current': self.current_path}})

    def on_double_click(self, event):
        sel = self.listbox.curselection()
        if not sel: return
        item = self.listbox.get(sel[0])

        if item.startswith("[DIR]"):
            folder_name = item.replace("[DIR] ", "").strip()
            sep = "\\" if "\\" in self.current_path else "/"
            new_path = f"{self.current_path}{sep}{folder_name}" if self.current_path != "/" else f"/{folder_name}"
            self.request_dir(new_path)

    def download_file(self):
        sel = self.listbox.curselection()
        if not sel: return
        item = self.listbox.get(sel[0])

        if item.startswith("[DIR]"):
            messagebox.showwarning("Notice", "You can only download files, not folders.")
            return

        filename = item.split("  |  ")[0].strip()
        sep = "\\" if "\\" in self.current_path else "/"
        target_path = f"{self.current_path}{sep}{filename}"

        save_path = filedialog.asksaveasfilename(initialfile=filename)
        if save_path:
            self.download_target = save_path
            self.btn_download.configure(text="Downloading...", state="disabled")
            open(self.download_target, 'wb').close()
            self.send_callback({'type': 'file_event', 'data': {'action': 'download', 'path': target_path}})

    # I/O Execution Layers: Dynamic multi-threaded file staging pipelines
    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path: return

        filename = os.path.basename(file_path)
        target_dir = self.current_path

        # Start a background thread so the UI doesn't freeze while chunking!
        threading.Thread(target=self._process_upload, args=(file_path, filename, target_dir), daemon=True).start()

    def _process_upload(self, local_path, filename, target_dir):
        try:
            self.root.after(0, lambda: self.btn_upload.configure(text="Uploading...", state="disabled"))

            with open(local_path, 'rb') as f:
                file_data = f.read()

            chunk_size = 40000
            total_chunks = max(1, (len(file_data) + chunk_size - 1) // chunk_size)

            for i in range(total_chunks):
                chunk = file_data[i * chunk_size: (i + 1) * chunk_size]
                b64_chunk = base64.b64encode(chunk).decode()

                self.send_callback({
                    'type': 'file_event',
                    'data': {
                        'action': 'upload_chunk',
                        'target_dir': target_dir,
                        'filename': filename,
                        'chunk_idx': i,
                        'total_chunks': total_chunks,
                        'chunk_data': b64_chunk
                    }
                })

                # Update the button with progress
                self.root.after(0, lambda idx=i, tot=total_chunks: self.btn_upload.configure(
                    text=f"Uploading... ({idx + 1}/{tot})"))
                time.sleep(0.02)  # Prevent network flooding

            # Finish up
            self.root.after(0, self._upload_complete)

        except Exception as e:
            print(f"Upload Error: {e}")
            self.root.after(0, lambda: self.btn_upload.configure(text="Upload File Here", state="normal"))

    def _upload_complete(self):
        self.btn_upload.configure(text="Upload File Here", state="normal")
        messagebox.showinfo("Success", "File uploaded successfully!")
        self.request_dir(self.current_path)  # Auto-refresh the list!

    def handle_response(self, cmd):
        resp_type = cmd.get('type')

        if resp_type == 'dir_result':
            self.current_path = cmd.get('path')
            self.lbl_path.configure(text=self.current_path)
            self.listbox.delete(0, 'end')
            for d in cmd.get('dirs', []):
                self.listbox.insert("end", f"[DIR] {d['name']}")
            for f in cmd.get('files', []):
                size_mb = f['size'] / (1024 * 1024)
                self.listbox.insert("end", f"{f['name']}  |  {size_mb:.2f} MB")

        elif resp_type == 'file_chunk':
            if not self.download_target: return

            chunk_data = base64.b64decode(cmd.get('data').encode())
            idx = cmd.get('chunk_idx')
            total = cmd.get('total_chunks')

            with open(self.download_target, 'ab') as f:
                f.write(chunk_data)

            self.btn_download.configure(text=f"Downloading... ({idx + 1}/{total})")

            if idx + 1 >= total:
                self.btn_download.configure(text="Download Selected", state="normal")
                messagebox.showinfo("Success", "File downloaded successfully!")
                self.download_target = None

    def close(self):
        self.active = False
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
        self.current_frame = None  # Storage buffer cache containing the most recently processed visualization matrix

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

        # Wire up the File Explorer Button
        self.file_explorer = None
        self.file_btn = ctk.CTkButton(self.root, text="Open File Explorer", command=self.open_file_explorer)
        self.file_btn.pack(pady=10)

        # Pass our secure network sender down into the Video window
        self.stream_window = VideoStreamWindow(self.root, self.host_username, self.send_rc_command)

        # Room Management: Workspace lifecycle control elements configuration
        self.leave_btn = ctk.CTkButton(self.root, text="Leave Room", command=self.close, fg_color="#cf3c3c",
                                       hover_color="#8f2727")
        self.leave_btn.pack(pady=25)

        # Fire up the background frame processor
        threading.Thread(target=self._video_loop, daemon=True).start()

        # Frame Rate Management: Schedules cyclical rendering routine ticks inside main loop context
        self.root.after(33, self._render_ui_loop)

    def open_file_explorer(self):
        if self.file_explorer is None or not self.file_explorer.active:
            self.file_explorer = FileExplorerWindow(self.root, self.host_username, self.send_rc_command)

    def toggle_rc(self):
        self.rc_active = not self.rc_active
        self.stream_window.rc_active = self.rc_active  # Tell the video screen to start listening
        if self.rc_active:
            self.rc_btn.configure(text="Remote Control: ON", fg_color="#006400", hover_color="#004d00")
        else:
            self.rc_btn.configure(text="Toggle Remote Control", fg_color=['#3a7ebf', '#1f538d'])

    def send_rc_command(self, cmd_dict):
        """Encrypts and fires the input commands instantly to the Room"""
        # Event Validation Override: Disengage toggle limits exclusively for active file requests
        if (self.rc_active or cmd_dict.get('type') == 'file_event') and self.app.relay_sock:
            try:
                payload = json.dumps({"t": "MSG", "m": self.fernet.encrypt(json.dumps(cmd_dict).encode()).decode()})
                self.app.safe_send(self.app.sec.wrap(self.app.username, 0, self.gid, payload.encode()))
            except Exception as e:
                print(f"Network Error: {e}")

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

        elif p_type == 0:
            try:
                data = json.loads(payload.decode())
                if data.get('t') == 'MSG':
                    cmd = json.loads(self.fernet.decrypt(data['m'].encode()).decode())
                    if self.file_explorer and self.file_explorer.active:
                        self.root.after(0, self.file_explorer.handle_response, cmd)
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

                    # Stage rendered framework metrics into target reference cache to separate concerns from display driver thread
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

    # Network Synchronization: Thread-safe operational sockets wrapper configuration

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

        # Component Additions: Global framework layout kill switch implementation
        self.btn_quit_dash = ctk.CTkButton(
            self.dash_frame,
            text="Quit Application",
            command=self.root.destroy,
            fg_color="#cf3c3c",
            hover_color="#8f2727"
        )
        self.btn_quit_dash.grid(row=2, column=0, columnspan=2, pady=(0, 10))

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

                # Security Guardrails: Interrupt loop and tear down framework context if registration validation rejects target client parameters
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

                        # User Tracking: Append validated remote user parameters to the view matrix
                        if hasattr(self, 'host_hub') and self.host_hub:
                            self.root.after(0, self.host_hub.add_user, sender)

                    elif data.get('t') == 'INV':
                        room = data['room']
                        aes_key = self.sec.rsa_decrypt(self.priv, base64.b64decode(data['k']))
                        self.safe_send(self.sec.wrap(self.username, 1, room, json.dumps({'a': 'JOIN'}).encode()))
                        self.root.after(0, lambda s=sender, r=room, k=aes_key: self._launch_viewer(s, r, k))

                        # Room Lifecycle Control: Systematic teardown routine allocations

                    elif data.get('t') == 'KICK' or data.get('t') == 'DISBAND':
                        room = data['room']
                        if room in self.viewers:
                            # Forcefully close the viewer window on the UI thread
                            self.root.after(0, self.viewers[room].force_close, data.get('t'))

                    elif data.get('t') == 'LEAVE' and self.host_engine:
                        # A viewer voluntarily closed their window, remove them from the Host Hub!
                        if hasattr(self, 'host_hub') and self.host_hub:
                            self.root.after(0, self.host_hub.remove_user, sender)

                # Process packets bound to HostEngine instances
                elif gid == self.hosted_gid and self.host_engine:
                    self.host_engine.route_incoming(sender, p_type, payload)

                # 1. Catches Multicast Room Data (Video Streams)
                elif gid in self.viewers:
                    self.viewers[gid].route_incoming(sender, p_type, payload)

                # 2. Identity Routing Layer: Intercepts discrete payload metrics aimed straight at local client parameters
                elif gid == self.username:
                    # Figure out which room this Host belongs to, and pass them the data
                    expected_room = f"Room_{sender}"
                    if expected_room in self.viewers:
                        self.viewers[expected_room].route_incoming(sender, p_type, payload)

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