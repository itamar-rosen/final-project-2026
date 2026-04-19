# remote_protocol.py
import socket
import json
import struct


class NetworkProtocol:
    HEADER_SIZE = 4
    BUFFER_SIZE = 4096
    encoding = 'utf-8'

    # --- Core Transmission Logic ---
    @staticmethod
    def create_message(content: bytes) -> bytes:
        size = len(content)
        return size.to_bytes(NetworkProtocol.HEADER_SIZE, 'big') + content

    @staticmethod
    def get_message(sock: socket.socket, timeout: float = None) -> bytes:
        if timeout is not None:
            sock.settimeout(timeout)
        try:
            header_bytes = NetworkProtocol._recv_all(sock, NetworkProtocol.HEADER_SIZE)
            if not header_bytes:
                return None
            msg_len = int.from_bytes(header_bytes, 'big')
            if msg_len == 0:
                return b""
            return NetworkProtocol._recv_all(sock, msg_len)
        except socket.timeout:
            raise TimeoutError("Socket timed out waiting for data.")
        finally:
            if timeout is not None:
                sock.settimeout(None)

    @staticmethod
    def _recv_all(sock: socket.socket, n: int) -> bytes:
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    @staticmethod
    def send_json(sock: socket.socket, data: dict):
        payload = json.dumps(data).encode(NetworkProtocol.encoding)
        sock.sendall(NetworkProtocol.create_message(payload))

    @staticmethod
    def receive_json(sock: socket.socket, timeout: float = None) -> dict:
        data = NetworkProtocol.get_message(sock, timeout)
        if data is None:
            raise ConnectionError("Connection closed by peer.")
        if data == b"":
            return None
        return json.loads(data.decode(NetworkProtocol.encoding))

    # --- File Stream Logic ---
    @staticmethod
    def send_stream(sock: socket.socket, file_handle, size: int):
        bytes_sent = 0
        while bytes_sent < size:
            chunk = file_handle.read(min(NetworkProtocol.BUFFER_SIZE, size - bytes_sent))
            if not chunk:
                break
            sock.sendall(chunk)
            bytes_sent += len(chunk)

    @staticmethod
    def receive_stream_to_file(sock: socket.socket, file_handle, size: int):
        bytes_received = 0
        while bytes_received < size:
            chunk_size = min(NetworkProtocol.BUFFER_SIZE, size - bytes_received)
            chunk = sock.recv(chunk_size)
            if not chunk:
                raise ConnectionError("Connection lost during stream receive.")
            file_handle.write(chunk)
            bytes_received += len(chunk)

    # --- Client-to-Server Command Builders ---
    @staticmethod
    def send_auth(sock, password):
        NetworkProtocol.send_json(sock, {"type": "auth", "password": password})

    @staticmethod
    def send_mouse_event(sock, action, x, y, button=None, clicks=None):
        data = {"action": action, "x": x, "y": y}
        if button: data["button"] = button
        if clicks: data["clicks"] = clicks
        NetworkProtocol.send_json(sock, {"type": "mouse_event", "data": data})

    @staticmethod
    def send_keyboard_event(sock, action, key_name, text=None, keys=None):
        data = {"action": action, "key_name": key_name}
        if text: data["text"] = text
        if keys: data["keys"] = keys
        NetworkProtocol.send_json(sock, {"type": "keyboard_event", "data": data})

    @staticmethod
    def send_list_dir(sock, path="."):
        NetworkProtocol.send_json(sock, {"type": "list_dir", "path": path})

    @staticmethod
    def send_get_file_request(sock, remote_path):
        NetworkProtocol.send_json(sock, {"type": "get_file", "path": remote_path})

    @staticmethod
    def send_put_file_start(sock, remote_path, file_size):
        NetworkProtocol.send_json(sock, {"type": "put_file_start", "path": remote_path, "size": file_size})

    @staticmethod
    def send_execute_command(sock, command_str):
        NetworkProtocol.send_json(sock, {"type": "execute_command", "command_str": command_str})

    @staticmethod
    def send_start_stream(sock):
        NetworkProtocol.send_json(sock, {"type": "start_screen_stream"})

    @staticmethod
    def send_stop_stream(sock):
        NetworkProtocol.send_json(sock, {"type": "stop_screen_stream"})

    @staticmethod
    def send_ack(sock, status="ready_to_receive"):
        NetworkProtocol.send_json(sock, {"type": "ack", "status": status})

    # --- Server-to-Client Response Builders ---
    @staticmethod
    def send_success(sock, message="ok", **kwargs):
        data = {"status": "ok", "message": message}
        data.update(kwargs)
        NetworkProtocol.send_json(sock, data)

    @staticmethod
    def send_error(sock, message="error"):
        NetworkProtocol.send_json(sock, {"status": "error", "message": message})