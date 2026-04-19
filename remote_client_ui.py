# remote_client_ui.py
import socket
import json
import threading
import time
import os
import queue

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import customtkinter as ctk

from remote_protocol import NetworkProtocol

try:
    from pynput import mouse, keyboard

    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    print("WARNING: pynput library not found.")

try:
    import cv2
    import numpy as np

    VIDEO_CAPABLE = True
except ImportError:
    VIDEO_CAPABLE = False
    print("WARNING: OpenCV (cv2) or NumPy not found.")

BUFFER_SIZE = 4096
DEFAULT_SAVE_DIR = os.path.expanduser("~/remote_downloads")
MOUSE_MOVE_THROTTLE_INTERVAL = 0.02
VIDEO_WINDOW_NAME_BASE = "Remote Screen Stream"

# Apply Dark Mode to the application
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class RemoteClient:
    def __init__(self, session_ui_handler, server_host, server_port_str, server_name="Unknown"):
        self.session_ui_handler = session_ui_handler
        self.server_name = server_name
        self.server_host = server_host
        self.server_port_str = server_port_str

        self.control_sock = None
        self.connected = False

        self.remote_control_active = False
        self.mouse_listener = None
        self.keyboard_listener = None
        self.last_mouse_pos = None
        self.last_mouse_move_time = 0

        self.video_sock = None
        self.video_stream_active = False
        self.video_stop_event = threading.Event()
        self.video_receive_thread = None
        self.video_window_name = f"{VIDEO_WINDOW_NAME_BASE} ({self.server_name})"

    def _receive_control_response(self, timeout=5.0):
        if not self.control_sock:
            raise ConnectionError("Control socket not initialized.")
        try:
            response = NetworkProtocol.receive_json(self.control_sock, timeout)
            if response is None:
                self._handle_unexpected_disconnect()
                raise ConnectionError("Connection closed by server.")
            return response
        except Exception as e:
            self._handle_unexpected_disconnect()
            raise ConnectionError(f"Control socket error during receive: {e}")

    def _handle_unexpected_disconnect(self):
        if self.connected and self.session_ui_handler:
            self.session_ui_handler.log_message("Disconnected from server.", "ERROR")
        self.connected = False
        if self.video_stream_active:
            self.video_stop_event.set()
            self.video_stream_active = False

    def connect_control_channel(self, host, port, password):
        try:
            if self.connected or self.control_sock:
                self.disconnect_all()

            self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.control_sock.connect((host, int(port)))

            NetworkProtocol.send_auth(self.control_sock, password)
            response = self._receive_control_response()

            if response.get("status") == "ok":
                self.connected = True
                return True, response.get("message", "Connected successfully.")
            else:
                self.disconnect_all()
                return False, response.get("message", "Authentication failed.")
        except Exception as e:
            self.disconnect_all()
            return False, f"Connection failed: {str(e)}"

    def disconnect_all(self):
        if self.video_stream_active:
            self.stop_video_stream(initiated_by_disconnect=True)
        self.stop_remote_input_control()
        if self.control_sock:
            try:
                self.control_sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            finally:
                self.control_sock.close()
        self.control_sock = None
        self.connected = False

    def list_directory(self, path="."):
        if not self.connected: return None, "Not connected."
        try:
            NetworkProtocol.send_list_dir(self.control_sock, path)
            response = self._receive_control_response(timeout=10.0)
            if response.get("status") == "ok":
                return response.get("listing", []), response.get("path", path)
            return None, response.get("message", "Failed to list directory.")
        except Exception as e:
            return None, str(e)

    def download_file(self, remote_path, save_dir):
        if not self.connected: return False, "Not connected."
        original_timeout = None
        try:
            NetworkProtocol.send_get_file_request(self.control_sock, remote_path)
            response = self._receive_control_response(timeout=10.0)
            if response.get("status") != "ok":
                return False, response.get("message", "Server error.")

            filename, file_size = response.get("filename"), response.get("size")
            local_filepath = os.path.join(save_dir, filename)
            os.makedirs(save_dir, exist_ok=True)

            NetworkProtocol.send_ack(self.control_sock, "ready_to_receive")

            with open(local_filepath, 'wb') as f:
                if self.control_sock: original_timeout = self.control_sock.gettimeout()
                self.control_sock.settimeout(30.0)
                NetworkProtocol.receive_stream_to_file(self.control_sock, f, file_size)

            return True, f"File '{filename}' downloaded."
        except Exception as e:
            return False, str(e)
        finally:
            if self.control_sock and self.connected:
                try:
                    self.control_sock.settimeout(original_timeout)
                except:
                    pass

    def upload_file(self, local_path, remote_filename):
        if not self.connected: return False, "Not connected."
        try:
            file_size = os.path.getsize(local_path)
            NetworkProtocol.send_put_file_start(self.control_sock, remote_filename, file_size)
            ack_response = self._receive_control_response(timeout=10.0)
            if ack_response.get("status") != "ready_to_receive":
                return False, ack_response.get("message", "Server not ready.")

            with open(local_path, 'rb') as f:
                NetworkProtocol.send_stream(self.control_sock, f, file_size)

            final_response = self._receive_control_response(timeout=15.0)
            if final_response.get("status") == "ok":
                return True, f"File uploaded."
            return False, final_response.get("message", "Server failed to save.")
        except Exception as e:
            return False, str(e)

    def execute_remote_command(self, command_str):
        if not self.connected: return None, "Not connected."
        try:
            NetworkProtocol.send_execute_command(self.control_sock, command_str)
            response = self._receive_control_response(timeout=30.0)
            return response.get("output", response.get("message", "No output.")), response.get("status")
        except Exception as e:
            return str(e), "error"

    def on_move(self, x, y):
        if self.remote_control_active and self.connected:
            current_time = time.time()
            if (current_time - self.last_mouse_move_time) > MOUSE_MOVE_THROTTLE_INTERVAL:
                if self.last_mouse_pos != (x, y):
                    self.last_mouse_pos = (x, y)
                    self.last_mouse_move_time = current_time
                    try:
                        NetworkProtocol.send_mouse_event(self.control_sock, "move", x, y)
                    except:
                        self.stop_remote_input_control()

    def on_click(self, x, y, button, pressed):
        if self.remote_control_active and self.connected:
            action = 'press' if pressed else 'release'
            btn_name = str(button).split('.')[-1]
            try:
                NetworkProtocol.send_mouse_event(self.control_sock, action, x, y, button=btn_name)
            except:
                self.stop_remote_input_control()

    def on_scroll(self, x, y, dx, dy):
        if self.remote_control_active and self.connected:
            try:
                NetworkProtocol.send_mouse_event(self.control_sock, "scroll", x, y, clicks=-dy)
            except:
                self.stop_remote_input_control()

    def on_press(self, key):
        if self.remote_control_active and self.connected:
            try:
                key_name = key.char
            except AttributeError:
                key_name = str(key).split('.')[-1]
            if key_name and key_name.startswith("Key."): key_name = key_name[4:]
            if hasattr(key, 'vk') and key.vk and 96 <= key.vk <= 105: key_name = str(key.vk - 96)
            try:
                NetworkProtocol.send_keyboard_event(self.control_sock, "press", key_name.lower())
            except:
                self.stop_remote_input_control()

    def on_release(self, key):
        if self.remote_control_active and self.connected:
            try:
                key_name = key.char
            except AttributeError:
                key_name = str(key).split('.')[-1]
            if key_name and key_name.startswith("Key."): key_name = key_name[4:]
            if hasattr(key, 'vk') and key.vk and 96 <= key.vk <= 105: key_name = str(key.vk - 96)
            try:
                NetworkProtocol.send_keyboard_event(self.control_sock, "release", key_name.lower())
            except:
                self.stop_remote_input_control()

    def start_remote_input_control(self):
        if not PYNPUT_AVAILABLE or not self.connected: return False
        if self.remote_control_active: return True
        self.last_mouse_move_time = 0
        try:
            self.mouse_listener = mouse.Listener(on_move=self.on_move, on_click=self.on_click, on_scroll=self.on_scroll)
            self.keyboard_listener = keyboard.Listener(on_press=self.on_press, on_release=self.on_release)
            self.mouse_listener.start()
            self.keyboard_listener.start()
            self.remote_control_active = True
            return True
        except:
            self.stop_remote_input_control()
            return False

    def stop_remote_input_control(self):
        if self.mouse_listener:
            try:
                self.mouse_listener.stop()
            except:
                pass
            self.mouse_listener = None
        if self.keyboard_listener:
            try:
                self.keyboard_listener.stop()
            except:
                pass
            self.keyboard_listener = None
        self.remote_control_active = False
        return True

    def start_video_stream(self):
        if not VIDEO_CAPABLE or not self.connected or self.video_stream_active: return False
        try:
            NetworkProtocol.send_start_stream(self.control_sock)

            start_wait_time = time.time()
            video_port_response = None

            while time.time() - start_wait_time < 10.0:
                try:
                    resp = self._receive_control_response(timeout=1.0)
                    if resp and resp.get("status") == "ok" and "video_port" in resp:
                        video_port_response = resp
                        break
                except TimeoutError:
                    pass

            if video_port_response:
                video_port = video_port_response["video_port"]
                self.video_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.video_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.video_sock.connect((self.server_host, video_port))
                self.video_stop_event.clear()
                self.video_receive_thread = threading.Thread(target=self._receive_video_frames_loop, daemon=True)
                self.video_receive_thread.start()
                self.video_stream_active = True
                return True
            return False
        except Exception:
            if self.video_sock: self.video_sock.close(); self.video_sock = None
            return False

    def _receive_video_frames_loop(self):
        window_created = False
        try:
            while not self.video_stop_event.is_set():
                try:
                    jpeg_bytes = NetworkProtocol.get_message(self.video_sock)
                    if not jpeg_bytes: break

                    nparr = np.frombuffer(jpeg_bytes, np.uint8)
                    img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

                    if img_cv is not None:
                        img_to_display = cv2.cvtColor(img_cv, cv2.COLOR_BGR2RGB)
                        if not window_created:
                            cv2.namedWindow(self.video_window_name, cv2.WINDOW_NORMAL)
                            cv2.resizeWindow(self.video_window_name, 800, 600)
                            window_created = True

                        if cv2.getWindowProperty(self.video_window_name, cv2.WND_PROP_VISIBLE) >= 1:
                            cv2.imshow(self.video_window_name, img_to_display)
                        else:
                            self.video_stop_event.set()
                            if self.session_ui_handler and self.session_ui_handler.root.winfo_exists():
                                self.session_ui_handler.root.after(0,
                                                                   self.session_ui_handler.handle_video_window_close_event)
                            break

                        if (cv2.waitKey(1) & 0xFF) == ord('q'):
                            self.video_stop_event.set()
                            if self.session_ui_handler and self.session_ui_handler.root.winfo_exists():
                                self.session_ui_handler.root.after(0,
                                                                   self.session_ui_handler.handle_video_window_close_event)
                            break
                except:
                    break
        finally:
            if VIDEO_CAPABLE and window_created:
                try:
                    cv2.destroyWindow(self.video_window_name)
                except:
                    pass
            if self.video_sock:
                try:
                    self.video_sock.close()
                except:
                    pass
                self.video_sock = None

            was_active = self.video_stream_active
            self.video_stream_active = False
            if was_active and self.session_ui_handler and self.session_ui_handler.root.winfo_exists():
                self.session_ui_handler.root.after(0, self.session_ui_handler.update_ui_for_connection_status)

    def stop_video_stream(self, initiated_by_disconnect=False):
        self.video_stop_event.set()
        if not initiated_by_disconnect and self.connected and self.control_sock:
            try:
                NetworkProtocol.send_stop_stream(self.control_sock)
            except:
                pass
        self.video_stream_active = False
        return True


class ClientSessionWindow:
    def __init__(self, manager_app, server_name, server_host, server_port_str, server_password):
        self.manager_app = manager_app
        self.server_name = server_name
        self.server_host = server_host
        self.server_port_str = server_port_str
        self.server_password = server_password

        self.root = ctk.CTkToplevel(manager_app.root)
        self.root.title(f"Session: {server_name} ({server_host}:{server_port_str})")
        self.root.geometry("1000x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.client = RemoteClient(self, server_host, server_port_str, server_name)
        self.current_remote_path = "."

        # --- Style for Treeview in CTk ---
        style = ttk.Style(self.root)
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0,
                        rowheight=25)
        style.map('Treeview', background=[('selected', '#1f538d')])
        style.configure("Treeview.Heading", background="#333333", foreground="white", relief="flat",
                        font=('Helvetica', 11, 'bold'))
        style.map("Treeview.Heading", background=[('active', '#1f538d')])

        # Layout
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        # --- Left Pane (Controls) ---
        self.left_pane = ctk.CTkFrame(self.root, width=250, corner_radius=0)
        self.left_pane.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.left_pane.grid_rowconfigure(5, weight=1)

        self.status_label = ctk.CTkLabel(self.left_pane, text="Status: Connecting...", font=ctk.CTkFont(weight="bold"))
        self.status_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

        self.disconnect_btn = ctk.CTkButton(self.left_pane, text="Disconnect", fg_color="#C25A5A",
                                            hover_color="#964040", command=self.disconnect_from_server_gui)
        self.disconnect_btn.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        # Remote Control Frame
        self.rc_frame = ctk.CTkFrame(self.left_pane)
        self.rc_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        ctk.CTkLabel(self.rc_frame, text="Remote Input").pack(pady=(5, 0))
        self.rc_button_text = tk.StringVar(value="Start Remote Input")
        self.rc_btn = ctk.CTkButton(self.rc_frame, textvariable=self.rc_button_text, command=self.toggle_remote_control)
        self.rc_btn.pack(padx=10, pady=10, fill="x")

        # Stream Frame
        self.ss_frame = ctk.CTkFrame(self.left_pane)
        self.ss_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        ctk.CTkLabel(self.ss_frame, text="Screen Streaming").pack(pady=(5, 0))
        self.ss_button_text = tk.StringVar(value="Start Stream")
        self.ss_btn = ctk.CTkButton(self.ss_frame, textvariable=self.ss_button_text, command=self.toggle_video_stream)
        self.ss_btn.pack(padx=10, pady=10, fill="x")

        # --- Right Pane (Files & Command) ---
        self.right_pane = ctk.CTkFrame(self.root, fg_color="transparent")
        self.right_pane.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.right_pane.grid_rowconfigure(1, weight=1)
        self.right_pane.grid_columnconfigure(0, weight=1)

        # File Browser Header
        self.path_frame = ctk.CTkFrame(self.right_pane, fg_color="transparent")
        self.path_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self.up_dir_btn = ctk.CTkButton(self.path_frame, text="Up (..)", width=80, command=self.go_up_directory)
        self.up_dir_btn.pack(side="left", padx=(0, 10))
        self.current_path_label = ctk.CTkLabel(self.path_frame, text="Path: N/A", font=ctk.CTkFont(weight="bold"))
        self.current_path_label.pack(side="left", fill="x", expand=True)

        # Treeview (using standard tk since CTk lacks it, but styled above)
        self.tree_frame = ctk.CTkFrame(self.right_pane)
        self.tree_frame.grid(row=1, column=0, sticky="nsew")
        self.tree_frame.grid_columnconfigure(0, weight=1)
        self.tree_frame.grid_rowconfigure(0, weight=1)

        self.file_tree = ttk.Treeview(self.tree_frame, columns=("type", "path"), show="headings", selectmode="browse")
        self.file_tree.heading("type", text="Type")
        self.file_tree.column("type", width=80, stretch=False, anchor="center")
        self.file_tree.heading("path", text="Name")
        self.file_tree.column("path", width=400)
        self.file_tree.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        self.file_tree.bind("<Double-1>", self.on_file_tree_double_click)
        self.file_tree.bind("<<TreeviewSelect>>", self.on_file_tree_select)

        # File Actions
        self.file_actions = ctk.CTkFrame(self.right_pane, fg_color="transparent")
        self.file_actions.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        self.download_btn = ctk.CTkButton(self.file_actions, text="Download Selected",
                                          command=self.download_selected_file)
        self.download_btn.pack(side="left", padx=(0, 10))
        self.upload_btn = ctk.CTkButton(self.file_actions, text="Upload File Here",
                                        command=self.upload_file_to_current_dir)
        self.upload_btn.pack(side="left")

        # Remote Command
        self.cmd_frame = ctk.CTkFrame(self.right_pane)
        self.cmd_frame.grid(row=3, column=0, sticky="ew", pady=(20, 0))
        self.cmd_frame.grid_columnconfigure(0, weight=1)
        self.cmd_entry = ctk.CTkEntry(self.cmd_frame, placeholder_text="Enter system command...")
        self.cmd_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.cmd_btn = ctk.CTkButton(self.cmd_frame, text="Execute", width=100, command=self.execute_remote_cmd_gui)
        self.cmd_btn.grid(row=0, column=1, padx=(0, 10), pady=10)

        # Log
        self.log_text = ctk.CTkTextbox(self.root, height=100, state="disabled")
        self.log_text.grid(row=1, column=1, padx=20, pady=(0, 20), sticky="ew")

        self.update_ui_for_connection_status()
        self.log_message(f"Attempting to connect to {server_host}:{server_port_str}...")
        threading.Thread(target=self._initiate_connection, daemon=True).start()

    def _initiate_connection(self):
        success, message = self.client.connect_control_channel(self.server_host, self.server_port_str,
                                                               self.server_password)
        if self.root.winfo_exists():
            self.root.after(0, self._handle_connection_result, success, message)

    def _handle_connection_result(self, success, message):
        if success:
            self.log_message(f"Connected: {message}", "STATUS")
            self.current_remote_path = "."
            self.refresh_file_browser()
        else:
            self.log_message(f"Connection failed: {message}", "ERROR")
            self.on_closing()
        self.update_ui_for_connection_status()

    def log_message(self, message, level="INFO"):
        if not self.log_text.winfo_exists(): return
        self.log_text.configure(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts} {level}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        if self.status_label.winfo_exists() and level in ["ERROR", "STATUS"]:
            self.status_label.configure(text=f"Status: {message[:40]}")

    def update_ui_for_connection_status(self):
        if not self.root.winfo_exists(): return
        c = self.client.connected

        self.disconnect_btn.configure(state="normal" if c else "disabled")
        self.rc_btn.configure(state="normal" if c and PYNPUT_AVAILABLE else "disabled")
        self.upload_btn.configure(state="normal" if c else "disabled")
        self.up_dir_btn.configure(state="normal" if c else "disabled")
        self.cmd_btn.configure(state="normal" if c else "disabled")

        if c and VIDEO_CAPABLE:
            self.ss_btn.configure(state="normal")
            self.ss_button_text.set("Stop Stream" if self.client.video_stream_active else "Start Stream")
        else:
            self.ss_btn.configure(state="disabled")
            self.ss_button_text.set("Start Stream")

        focus = self.file_tree.focus()
        can_dl = False
        if c and focus:
            vals = self.file_tree.item(focus, "values")
            if vals and vals[0] == 'file': can_dl = True
        self.download_btn.configure(state="normal" if can_dl else "disabled")

        if not c:
            self.status_label.configure(text="Status: Not Connected")
            self.file_tree.delete(*self.file_tree.get_children())

    def refresh_file_browser(self, path=None):
        if not self.client.connected: return
        tp = path if path else self.current_remote_path
        self.status_label.configure(text=f"Loading: {tp[:20]}...")
        threading.Thread(target=self._execute_refresh, args=(tp,), daemon=True).start()

    def _execute_refresh(self, tp):
        listing, actual_path = self.client.list_directory(tp)

        def _update():
            self.file_tree.delete(*self.file_tree.get_children())
            if listing is not None:
                self.current_remote_path = actual_path
                self.current_path_label.configure(text=f"Path: {actual_path}")
                if actual_path not in ["/", ".", "C:\\", "D:\\"]:
                    self.file_tree.insert("", 0, values=("dir", ".. (Parent)"), tags=('dir_item', actual_path))
                for i in sorted(listing, key=lambda x: (x['type'] != 'dir', x['name'].lower())):
                    self.file_tree.insert("", "end", values=(i['type'], i['name']), tags=(i['type'], i['path']))
                self.status_label.configure(text="Status: Ready")
            self.update_ui_for_connection_status()

        if self.root.winfo_exists(): self.root.after(0, _update)

    def on_file_tree_select(self, event):
        self.update_ui_for_connection_status()

    def on_file_tree_double_click(self, event):
        item = self.file_tree.focus()
        if not item: return
        vals = self.file_tree.item(item, "values")
        tags = self.file_tree.item(item, "tags")
        if vals[1] == ".. (Parent)":
            self.go_up_directory()
        elif vals[0] == "dir":
            self.refresh_file_browser(tags[1])
        elif vals[0] == "file":
            self.download_selected_file()

    def go_up_directory(self):
        parent = os.path.dirname(os.path.normpath(self.current_remote_path))
        if parent == self.current_remote_path and parent != ".":
            self.refresh_file_browser(".")
            return
        self.refresh_file_browser(parent)

    def download_selected_file(self):
        item = self.file_tree.focus()
        if not item: return
        tags = self.file_tree.item(item, "tags")
        vals = self.file_tree.item(item, "values")
        save_dir = filedialog.askdirectory(initialdir=DEFAULT_SAVE_DIR)
        if not save_dir: return
        self.status_label.configure(text=f"Downloading {vals[1]}...")
        self.download_btn.configure(state="disabled")
        threading.Thread(target=self._dl_thread, args=(tags[1], save_dir, vals[1]), daemon=True).start()

    def _dl_thread(self, rpath, sdir, fname):
        success, msg = self.client.download_file(rpath, sdir)

        def _done():
            self.log_message(msg, "INFO" if success else "ERROR")
            self.update_ui_for_connection_status()

        if self.root.winfo_exists(): self.root.after(0, _done)

    def upload_file_to_current_dir(self):
        lpath = filedialog.askopenfilename()
        if not lpath: return
        fname = os.path.basename(lpath)
        rpath = os.path.join(self.current_remote_path, fname).replace("\\", "/")
        self.upload_btn.configure(state="disabled")
        threading.Thread(target=self._ul_thread, args=(lpath, rpath, fname), daemon=True).start()

    def _ul_thread(self, lp, rp, fn):
        success, msg = self.client.upload_file(lp, rp)

        def _done():
            self.log_message(msg, "INFO" if success else "ERROR")
            if success: self.refresh_file_browser()
            self.update_ui_for_connection_status()

        if self.root.winfo_exists(): self.root.after(0, _done)

    def toggle_remote_control(self):
        if self.client.remote_control_active:
            self.client.stop_remote_input_control()
            self.rc_button_text.set("Start Remote Input")
        else:
            if self.client.start_remote_input_control():
                self.rc_button_text.set("Stop Remote Input")
        self.update_ui_for_connection_status()

    def toggle_video_stream(self):
        self.ss_btn.configure(state="disabled")
        if self.client.video_stream_active:
            threading.Thread(target=self.client.stop_video_stream, daemon=True).start()
        else:
            threading.Thread(target=self.client.start_video_stream, daemon=True).start()
        self.root.after(500, self.update_ui_for_connection_status)

    def handle_video_window_close_event(self):
        self.client.stop_video_stream()
        self.update_ui_for_connection_status()

    def execute_remote_cmd_gui(self):
        cmd = self.cmd_entry.get()
        if not cmd: return
        self.cmd_btn.configure(state="disabled")
        threading.Thread(target=self._cmd_thread, args=(cmd,), daemon=True).start()

    def _cmd_thread(self, cmd):
        out, status = self.client.execute_remote_command(cmd)

        def _done():
            self.log_message(f"CMD Out:\n{out}", "INFO" if status == "ok" else "ERROR")
            self.cmd_entry.delete(0, 'end')
            self.update_ui_for_connection_status()

        if self.root.winfo_exists(): self.root.after(0, _done)

    def disconnect_from_server_gui(self):
        self.client.disconnect_all()
        self.manager_app.active_sessions.remove(self)
        self.root.destroy()

    def on_closing(self):
        self.client.disconnect_all()
        if VIDEO_CAPABLE:
            try:
                cv2.destroyWindow(self.client.video_window_name)
            except:
                pass
        if self in self.manager_app.active_sessions:
            self.manager_app.active_sessions.remove(self)
        self.root.destroy()


class RemoteControlApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Remote Control Manager")
        self.root.geometry("650x600")

        self.servers_list = []
        self.active_sessions = []

        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        # Main Layout
        self.server_frame = ctk.CTkFrame(self.root, corner_radius=10)
        self.server_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.server_frame.grid_columnconfigure(1, weight=1)
        self.server_frame.grid_rowconfigure(1, weight=1)

        self.title_lbl = ctk.CTkLabel(self.server_frame, text="Server Connections",
                                      font=ctk.CTkFont(size=20, weight="bold"))
        self.title_lbl.grid(row=0, column=0, columnspan=2, padx=20, pady=15, sticky="w")

        # Entry Form
        self.form_frame = ctk.CTkFrame(self.server_frame, fg_color="transparent")
        self.form_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nw")

        self.s_name = ctk.CTkEntry(self.form_frame, placeholder_text="Name")
        self.s_name.pack(pady=5, fill="x")
        self.s_host = ctk.CTkEntry(self.form_frame, placeholder_text="Host/IP (127.0.0.1)")
        self.s_host.pack(pady=5, fill="x")
        self.s_port = ctk.CTkEntry(self.form_frame, placeholder_text="Port (65432)")
        self.s_port.pack(pady=5, fill="x")
        self.s_pass = ctk.CTkEntry(self.form_frame, placeholder_text="Password", show="*")
        self.s_pass.pack(pady=5, fill="x")

        self.add_btn = ctk.CTkButton(self.form_frame, text="Add/Update", command=self.add_or_update)
        self.add_btn.pack(pady=15, fill="x")
        self.rem_btn = ctk.CTkButton(self.form_frame, text="Remove Selected", fg_color="#C25A5A", hover_color="#964040",
                                     command=self.remove_selected)
        self.rem_btn.pack(pady=5, fill="x")

        # List Area
        self.list_frame = ctk.CTkFrame(self.server_frame, fg_color="transparent")
        self.list_frame.grid(row=1, column=1, padx=(0, 20), pady=10, sticky="nsew")
        self.list_frame.grid_rowconfigure(0, weight=1)
        self.list_frame.grid_columnconfigure(0, weight=1)

        self.lb = tk.Listbox(self.list_frame, bg="#2b2b2b", fg="white", selectbackground="#1f538d", relief="flat",
                             highlightthickness=0, font=("Helvetica", 12))
        self.lb.grid(row=0, column=0, sticky="nsew")
        self.lb.bind('<<ListboxSelect>>', self.on_select)

        self.conn_btn = ctk.CTkButton(self.list_frame, text="Connect", height=40, font=ctk.CTkFont(weight="bold"),
                                      command=self.launch_session)
        self.conn_btn.grid(row=1, column=0, pady=15, sticky="ew")

        # Logs
        self.log_text = ctk.CTkTextbox(self.root, height=120, state="disabled")
        self.log_text.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="ew")

        self.load_config()
        self.update_list()

    def log_message(self, msg, lvl="INFO"):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{lvl}] {msg}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def add_or_update(self):
        n, h, p, pwd = self.s_name.get(), self.s_host.get(), self.s_port.get(), self.s_pass.get()
        if not all([n, h, p]): return
        idx = next((i for i, s in enumerate(self.servers_list) if s[0] == n), -1)
        if idx != -1:
            self.servers_list[idx] = (n, h, p, pwd)
        else:
            self.servers_list.append((n, h, p, pwd))
        self.update_list()
        self.save_config()

    def remove_selected(self):
        sel = self.lb.curselection()
        if sel:
            name = self.lb.get(sel[0])
            self.servers_list = [s for s in self.servers_list if s[0] != name]
            self.update_list()
            self.save_config()

    def update_list(self):
        self.lb.delete(0, 'end')
        for s in self.servers_list: self.lb.insert('end', s[0])

    def on_select(self, event):
        sel = self.lb.curselection()
        if not sel: return
        details = next((s for s in self.servers_list if s[0] == self.lb.get(sel[0])), None)
        if details:
            for e, val in zip([self.s_name, self.s_host, self.s_port, self.s_pass], details):
                e.delete(0, 'end');
                e.insert(0, val)

    def load_config(self):
        if os.path.exists("servers.json"):
            try:
                with open("servers.json", "r") as f:
                    self.servers_list = json.load(f)
            except:
                pass

    def save_config(self):
        try:
            with open("servers.json", "w") as f:
                json.dump(self.servers_list, f)
        except:
            pass

    def launch_session(self):
        sel = self.lb.curselection()
        if not sel: return
        s = next((x for x in self.servers_list if x[0] == self.lb.get(sel[0])), None)
        if s:
            for session in self.active_sessions:
                if session.server_host == s[1] and session.server_port_str == s[2]:
                    return
            try:
                win = ClientSessionWindow(self, *s)
                self.active_sessions.append(win)
            except Exception as e:
                self.log_message(f"Launch failed: {e}", "ERROR")

    def on_closing(self):
        for s in list(self.active_sessions):
            try:
                s.on_closing()
            except:
                pass
        if VIDEO_CAPABLE:
            try:
                cv2.destroyAllWindows()
            except:
                pass
        self.root.destroy()


if __name__ == "__main__":
    os.makedirs(DEFAULT_SAVE_DIR, exist_ok=True)
    root = ctk.CTk()
    app = RemoteControlApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()