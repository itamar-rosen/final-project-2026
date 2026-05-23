import struct, json, subprocess, sys

def install_deps():
    for lib in ["cryptography"]:
        try:
            __import__(lib)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])

install_deps()
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class SecurityEngine:
    def __init__(self):
        # Header: [Target: 16b][Type: 1b][GroupID: 16b][Size: 4b] = 37 bytes
        self.header_format = "!16sB16sI"
        self.header_size = struct.calcsize(self.header_format)

    # --- PACKET FRAMING ---
    def wrap(self, target, p_type, gid, data_bytes):
        t_fixed = target.encode('utf-8').ljust(16)[:16]
        g_fixed = gid.encode('utf-8').ljust(16)[:16]
        return struct.pack(self.header_format, t_fixed, p_type, g_fixed, len(data_bytes)) + data_bytes

    def receive(self, sock):
        try:
            h_data = sock.recv(self.header_size)
            if not h_data: return None, None, None, None
            target, p_type, gid, size = struct.unpack(self.header_format, h_data)
            payload = b""
            while len(payload) < size:
                chunk = sock.recv(min(size - len(payload), 8192))
                if not chunk: break
                payload += chunk
            return target.decode().strip(), p_type, gid.decode().strip(), payload
        except: return None, None, None, None

    # --- ASYMMETRIC (RSA) ---
    def generate_rsa_keys(self):
        priv = rsa.generate_private_key(65537, 2048)
        pub = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return priv, pub

    def rsa_encrypt(self, pub_pem, data_bytes):
        key = serialization.load_pem_public_key(pub_pem.encode())
        return key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_decrypt(self, priv_obj, cipher_bytes):
        return priv_obj.decrypt(
            cipher_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # --- SYMMETRIC (AES/FERNET) ---
    def generate_session_key(self):
        return Fernet.generate_key()

    def aes_encrypt(self, key, plain_text):
        return Fernet(key).encrypt(plain_text.encode()).decode()

    def aes_decrypt(self, key, cipher_text):
        return Fernet(key).decrypt(cipher_text.encode()).decode()