import struct, json, subprocess, sys

class DependencyManager:
    # Dynamically verify and install required third-party dependencies if missing
    @staticmethod
    def install_deps():
        for lib in ["cryptography"]:
            try:
                __import__(lib)
            except ImportError:
                # Execute pip installation via the current Python executable environment
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib])

# Run dependency verification check before importing cryptographic modules
DependencyManager.install_deps()
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class SecurityEngine:
    def __init__(self):
        # Header structure configuration:
        # - Target destination: 16 bytes (string/char array)
        # - Packet type indicator: 1 byte (unsigned char)
        # - Group identifier: 16 bytes (string/char array)
        # - Payload size: 4 bytes (unsigned integer)
        # Network byte order encoding (!) applied for reliable cross-platform transmission
        self.header_format = "!16sB16sI"
        # Calculate total expected byte length of the network header (37 bytes total)
        self.header_size = struct.calcsize(self.header_format)

    # --- PACKET FRAMING ---
    # Packs network routing variables and raw data payload into a standardized binary packet
    def wrap(self, target, p_type, gid, data_bytes):
        # Pad or truncate strings to fit the fixed 16-byte block constraints
        t_fixed = target.encode('utf-8').ljust(16)[:16]
        g_fixed = gid.encode('utf-8').ljust(16)[:16]
        # Construct and serialize binary packet combining compiled header data and raw payload
        return struct.pack(self.header_format, t_fixed, p_type, g_fixed, len(data_bytes)) + data_bytes

    # Reads and parses an incoming structured network packet from an active socket connection
    def receive(self, sock):
        try:
            # Retrieve the fixed-size binary header first
            h_data = sock.recv(self.header_size)
            if not h_data: return None, None, None, None
            # Unpack the binary header to extract metadata and payload size boundaries
            target, p_type, gid, size = struct.unpack(self.header_format, h_data)
            payload = b""
            # Loop streaming until the full length specified by the header size field is fetched
            while len(payload) < size:
                chunk = sock.recv(min(size - len(payload), 8192))
                if not chunk: break
                payload += chunk
            # Return decoded metadata string values along with the recovered raw payload bytes
            return target.decode().strip(), p_type, gid.decode().strip(), payload
        except: return None, None, None, None

    # --- ASYMMETRIC (RSA) ---
    # Generates a standard 2048-bit RSA key pair for asymmetric cryptography operations
    def generate_rsa_keys(self):
        # Create a private key instance using the standard public exponent 65537
        priv = rsa.generate_private_key(65537, 2048)
        # Serialize public key object into a distribution-ready PEM-formatted string
        pub = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return priv, pub

    # Encrypts raw data bytes using a provided PEM public key string and secure OAEP padding
    def rsa_encrypt(self, pub_pem, data_bytes):
        # Deserialize the public key from its PEM string format
        key = serialization.load_pem_public_key(pub_pem.encode())
        # Execute asymmetric RSA encryption using optimal OAEP configurations with SHA-256 hashes
        return key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Decrypts encrypted cipher bytes using an instantiated RSA private key object
    def rsa_decrypt(self, priv_obj, cipher_bytes):
        # Execute asymmetric RSA decryption using matching OAEP verification parameters
        return priv_obj.decrypt(
            cipher_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # --- SYMMETRIC (AES/FERNET) ---
    # Generates a random, secure 32-byte key suitable for symmetric Fernet operations
    def generate_session_key(self):
        return Fernet.generate_key()

    # Encrypts a plaintext string using symmetric Fernet (AES-128 in CBC mode with HMAC authentication)
    def aes_encrypt(self, key, plain_text):
        return Fernet(key).encrypt(plain_text.encode()).decode()

    # Decrypts a Fernet-encrypted ciphertext string back into its original plaintext string format
    def aes_decrypt(self, key, cipher_text):
        return Fernet(key).decrypt(cipher_text.encode()).decode()