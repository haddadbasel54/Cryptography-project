import os
import hashlib
from typing import List, Tuple, Dict
import random
import math
import json
import base64
from pathlib import Path

"""
Secure Sound Access System
This system provides secure encryption and decryption of sound files using:
- LEA (Lightweight Encryption Algorithm) in CFB mode for data encryption
- RSA for secure key delivery
- Schnorr signatures for authentication
"""

class KeyManager:
    """Handles secure storage and loading of cryptographic keys"""
    
    def __init__(self, keys_dir: str = "secure_keys"):
        """
        Initialize key manager with directory for key storage
        Args:
            keys_dir (str): Directory to store key files
        """
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)
        
        # Key file paths
        self.rsa_private_file = self.keys_dir / "rsa_private.key"
        self.rsa_public_file = self.keys_dir / "rsa_public.key"
        self.schnorr_private_file = self.keys_dir / "schnorr_private.key"
        self.schnorr_public_file = self.keys_dir / "schnorr_public.key"
    
    def save_rsa_keys(self, private_key: dict, public_key: dict):
        """Save RSA keys to files"""
        # Save private key
        private_data = {
            'n': private_key['n'],
            'd': private_key['d'],
            'e': private_key['e']
        }
        with open(self.rsa_private_file, 'w') as f:
            json.dump(private_data, f)
        
        # Save public key
        public_data = {
            'n': public_key['n'],
            'e': public_key['e']
        }
        with open(self.rsa_public_file, 'w') as f:
            json.dump(public_data, f)
    
    def save_schnorr_keys(self, private_key: int, public_key: int):
        """Save Schnorr keys to files"""
        # Save private key
        with open(self.schnorr_private_file, 'w') as f:
            json.dump({'private_key': private_key}, f)
        
        # Save public key
        with open(self.schnorr_public_file, 'w') as f:
            json.dump({'public_key': public_key}, f)
    
    def load_rsa_keys(self) -> Tuple[dict, dict]:
        """Load RSA keys from files or generate new ones if not found"""
        try:
            # Load private key
            with open(self.rsa_private_file, 'r') as f:
                private_data = json.load(f)
            
            # Load public key
            with open(self.rsa_public_file, 'r') as f:
                public_data = json.load(f)
            
            return private_data, public_data
            
        except FileNotFoundError:
            return None, None
    
    def load_schnorr_keys(self) -> Tuple[int, int]:
        """Load Schnorr keys from files or generate new ones if not found"""
        try:
            # Load private key
            with open(self.schnorr_private_file, 'r') as f:
                private_data = json.load(f)
            
            # Load public key
            with open(self.schnorr_public_file, 'r') as f:
                public_data = json.load(f)
            
            return private_data['private_key'], public_data['public_key']
            
        except FileNotFoundError:
            return None, None

class LEA:
    """
    Lightweight Encryption Algorithm implementation
    Used for encrypting/decrypting the actual sound data
    """
    def __init__(self, key: bytes):
        """
        Initialize LEA with a 128-bit key
        Args:
            key (bytes): 16-byte encryption key
        """
        if len(key) != 16:
            raise ValueError("LEA requires a 128-bit key")
        self.key = key
        # Constants used in the key schedule
        self.delta = [
            0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
            0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
        ]
        self.rounds = 24
        # Generate round keys for encryption/decryption
        self.round_keys = self._generate_round_keys()
    
    def _generate_round_keys(self) -> List[List[int]]:
        """
        Generate round keys for each encryption round
        Returns:
            List[List[int]]: List of round keys
        """
        round_keys = []
        # Split the main key into 4 32-bit words
        temp = list(int.from_bytes(self.key[i:i+4], 'big') for i in range(0, 16, 4))
        
        # Generate keys for each round using rotation and XOR operations
        for i in range(self.rounds):
            T = [0] * 4
            T[0] = self._rol(temp[0] + self.delta[i % 4], 1)
            T[1] = self._rol(temp[1] + self.delta[i % 4], 3)
            T[2] = self._rol(temp[2] + self.delta[i % 4], 6)
            T[3] = self._rol(temp[3] + self.delta[i % 4], 11)
            round_keys.append(T)
            temp = T[:]
        
        return round_keys
    
    @staticmethod
    def _rol(value: int, n: int) -> int:
        """Rotate left operation for bit manipulation"""
        return ((value << n) | (value >> (32 - n))) & 0xFFFFFFFF
    
    @staticmethod
    def _ror(value: int, n: int) -> int:
        """Rotate right operation"""
        return ((value >> n) | (value << (32 - n))) & 0xFFFFFFFF

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Block size must be 16 bytes")
        
        # Convert block to 4 32-bit words
        words = list(int.from_bytes(block[i:i+4], 'big') for i in range(0, 16, 4))
        
        # Encryption rounds
        for i in range(self.rounds):
            words = self._encrypt_round(words, self.round_keys[i])
        
        # Convert back to bytes
        result = b''.join(w.to_bytes(4, 'big') for w in words)
        return result

    def _encrypt_round(self, words: List[int], round_key: List[int]) -> List[int]:
        temp = words[:]
        words[0] = self._rol((temp[0] ^ round_key[0]) + (temp[1] ^ round_key[1]), 9)
        words[1] = self._ror((temp[1] ^ round_key[1]) + (temp[2] ^ round_key[2]), 5)
        words[2] = self._ror((temp[2] ^ round_key[2]) + (temp[3] ^ round_key[3]), 3)
        words[3] = temp[0]
        return words

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Block size must be 16 bytes")
        
        words = list(int.from_bytes(block[i:i+4], 'big') for i in range(0, 16, 4))
        
        for i in range(self.rounds - 1, -1, -1):
            words = self._decrypt_round(words, self.round_keys[i])
        
        return b''.join(w.to_bytes(4, 'big') for w in words)

    def _decrypt_round(self, words: List[int], round_key: List[int]) -> List[int]:
        temp = words[:]
        words[0] = temp[3]
        words[1] = self._rol((temp[1] ^ round_key[1]) + (temp[2] ^ round_key[2]), 5)
        words[2] = self._rol((temp[2] ^ round_key[2]) + (temp[3] ^ round_key[3]), 3)
        words[3] = self._ror((temp[0] ^ round_key[0]) + (words[1] ^ round_key[1]), 9)
        return words

class CFBMode:
    """
    Cipher Feedback Mode implementation
    Provides stream cipher functionality using LEA block cipher
    """
    def __init__(self, cipher: LEA, iv: bytes):
        """
        Initialize CFB mode with cipher and IV
        Args:
            cipher (LEA): Instance of LEA cipher
            iv (bytes): 16-byte initialization vector
        """
        self.cipher = cipher
        self.iv = iv
        self.block_size = 16

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using CFB mode
        Args:
            data (bytes): Data to encrypt
        Returns:
            bytes: Encrypted data
        """
        # Add padding to make data length multiple of block size
        padded_data = self._pad(data)
        # Split data into blocks
        blocks = [padded_data[i:i+self.block_size] for i in range(0, len(padded_data), self.block_size)]
        
        result = b''
        prev_block = self.iv # Start with IV
        
        # Process each block
        for block in blocks:
            # Encrypt previous block (or IV for first block)
            encrypted_prev = self.cipher.encrypt_block(prev_block)
            # XOR with current block to get ciphertext
            encrypted_block = bytes(a ^ b for a, b in zip(encrypted_prev, block))
            result += encrypted_block
            prev_block = encrypted_block # Use current ciphertext as next IV
        
        return result

    def decrypt(self, data: bytes) -> bytes:
        blocks = [data[i:i+self.block_size] for i in range(0, len(data), self.block_size)]
        
        result = b''
        prev_block = self.iv
        
        for block in blocks:
            # Encrypt previous block
            encrypted_prev = self.cipher.encrypt_block(prev_block)
            # XOR with current block
            decrypted_block = bytes(a ^ b for a, b in zip(encrypted_prev, block))
            result += decrypted_block
            prev_block = block
        
        return self._unpad(result)

    @staticmethod
    def _pad(data: bytes) -> bytes:
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length]) * padding_length
        return data + padding

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        padding_length = data[-1]
        return data[:-padding_length]

class RSA:
    """RSA implementation with persistent key storage"""
    
    def __init__(self, key_manager: KeyManager, key_size=2048):
        """
        Initialize RSA with key manager
        Args:
            key_manager (KeyManager): Instance of key manager
            key_size (int): Size of RSA key in bits
        """
        self.key_manager = key_manager
        self.key_size = key_size
        
        # Try to load existing keys
        private_data, public_data = key_manager.load_rsa_keys()
        
        if private_data and public_data:
            # Use existing keys
            self.e = private_data['e']
            self.d = private_data['d']
            self.n = private_data['n']
        else:
            # Generate new keys
            self.e = 65537
            self.p, self.q = self._generate_primes()
            self.n = self.p * self.q
            phi = (self.p - 1) * (self.q - 1)
            self.d = self._mod_inverse(self.e, phi)
            
            # Save new keys
            private_key = {'n': self.n, 'd': self.d, 'e': self.e}
            public_key = {'n': self.n, 'e': self.e}
            key_manager.save_rsa_keys(private_key, public_key)
            
    def _is_prime(self, n: int, k=128) -> bool:
        """Miller-Rabin primality test"""
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2

        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _generate_prime(self, bits: int) -> int:
        """Generate a prime number of specified bits"""
        while True:
            p = random.getrandbits(bits)
            p |= (1 << bits - 1) | 1  # Make sure it's odd and has correct bit length
            if self._is_prime(p):
                return p

    def _generate_primes(self) -> Tuple[int, int]:
        """Generate two distinct primes for RSA"""
        p = self._generate_prime(self.key_size // 2)
        while True:
            q = self._generate_prime(self.key_size // 2)
            if q != p:
                return p, q

    @staticmethod
    def _mod_inverse(a: int, m: int) -> int:
        """Calculate modular multiplicative inverse"""
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        _, x, _ = extended_gcd(a, m)
        return (x % m + m) % m

    def encrypt(self, message: bytes) -> bytes:
        m = int.from_bytes(message, 'big')
        if m >= self.n:
            raise ValueError("Message too large")
        c = pow(m, self.e, self.n)
        return c.to_bytes((c.bit_length() + 7) // 8, 'big')

    def decrypt(self, ciphertext: bytes) -> bytes:
        c = int.from_bytes(ciphertext, 'big')
        m = pow(c, self.d, self.n)
        return m.to_bytes((m.bit_length() + 7) // 8, 'big')

class SchnorrSignature:
    """Schnorr signature implementation with persistent key storage"""
    
    def __init__(self, key_manager: KeyManager):
        """
        Initialize Schnorr signature with key manager
        Args:
            key_manager (KeyManager): Instance of key manager
        """
        self.key_manager = key_manager
        self.p = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16)
        self.q = (self.p - 1) // 2
        self.g = 2
        
        # Try to load existing keys
        private_key, public_key = key_manager.load_schnorr_keys()
        
        if private_key and public_key:
            # Use existing keys
            self.private_key = private_key
            self.public_key = public_key
        else:
            # Generate new keys
            self.private_key, self.public_key = self.generate_keypair()
            # Save new keys
            key_manager.save_schnorr_keys(self.private_key, self.public_key)

    def generate_keypair(self) -> Tuple[int, int]:
        private_key = random.randrange(1, self.q)
        public_key = pow(self.g, private_key, self.p)
        return private_key, public_key

    def sign(self, message: bytes, private_key: int) -> Tuple[int, int]:
        k = random.randrange(1, self.q)
        r = pow(self.g, k, self.p)
        e = int.from_bytes(hashlib.sha256(message + str(r).encode()).digest(), 'big')
        s = (k - private_key * e) % self.q
        return r, s

    def verify(self, message: bytes, signature: Tuple[int, int], public_key: int) -> bool:
        r, s = signature
        if not (0 < r < self.p and 0 < s < self.q):
            return False
        e = int.from_bytes(hashlib.sha256(message + str(r).encode()).digest(), 'big')
        rv = (pow(self.g, s, self.p) * pow(public_key, e, self.p)) % self.p
        return rv == r

class SecureSoundAccess:
    """Main class combining all security components with persistent keys"""
    
    def __init__(self):
        """Initialize security components with persistent key storage"""
        # Initialize key manager
        self.key_manager = KeyManager()
        
        # Initialize components with key manager
        self.rsa = RSA(self.key_manager)
        self.schnorr = SchnorrSignature(self.key_manager)

    def encrypt_sound_file(self, sound_data: bytes) -> Dict:
        """
        Encrypt sound file data with public keys in metadata
        """
        # Generate random LEA key and IV
        lea_key = os.urandom(16)
        iv = os.urandom(16)
        
        # Encrypt LEA key with RSA
        encrypted_key = self.rsa.encrypt(lea_key)
        
        # Initialize LEA and CFB mode
        lea = LEA(lea_key)
        cfb = CFBMode(lea, iv)
        
        # Encrypt sound data
        encrypted_data = cfb.encrypt(sound_data)
        
        # Sign with persistent Schnorr key
        signature = self.schnorr.sign(encrypted_data, self.schnorr.private_key)
        
        return {
            'encrypted_key': encrypted_key,
            'iv': iv,
            'encrypted_data': encrypted_data,
            'signature': signature,
            'rsa_public_key': {
            'n': self.rsa.n,
            'e': self.rsa.e
            },
            'schnorr_public_key': self.schnorr.public_key
        }

    def decrypt_sound_file(self, encrypted_package: Dict) -> bytes:
        """
        Decrypt sound file data using public keys from metadata
        """
        # Verify signature using public key from metadata
        schnorr_verifier = SchnorrSignature(self.key_manager)
        if not schnorr_verifier.verify(
            encrypted_package['encrypted_data'],
            encrypted_package['signature'],
            encrypted_package['schnorr_public_key']
        ):
            raise ValueError("Invalid signature")
        
        # Convert encrypted key to hex string if it's bytes
        encrypted_key = encrypted_package['encrypted_key']
        if isinstance(encrypted_key, bytes):
            encrypted_key = encrypted_key.hex()
        
        # Decrypt key
        temp_rsa = RSA(self.key_manager)
        temp_rsa.n = encrypted_package['rsa_public_key']['n']
        temp_rsa.e = encrypted_package['rsa_public_key']['e']
        temp_rsa.d = self.rsa.d
        
        lea_key = temp_rsa.decrypt(bytes.fromhex(encrypted_key))
        
        # Ensure exactly 16 bytes
        if len(lea_key) > 16:
            lea_key = lea_key[-16:]
        elif len(lea_key) < 16:
            lea_key = lea_key.rjust(16, b'\x00')
        
        # Convert IV to bytes
        iv = encrypted_package['iv']
        if isinstance(iv, str):
            iv = bytes.fromhex(iv)
        
        # Initialize decryption
        lea = LEA(lea_key)
        cfb = CFBMode(lea, iv)
        
        return cfb.decrypt(encrypted_package['encrypted_data'])

def main():
    """Enhanced main function with persistent key handling"""
    secure_system = SecureSoundAccess()
    
    while True:
        print("\nSecure Sound Access System")
        print("1. Encrypt sound file")
        print("2. Decrypt sound file")
        print("3. Show public keys")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            try:
                input_file = input("Enter path to sound file: ")
                with open(input_file, 'rb') as f:
                    sound_data = f.read()
                
                encrypted = secure_system.encrypt_sound_file(sound_data)
                
                # Save encrypted file and metadata
                encrypted_file = input_file + '.encrypted'
                meta_file = input_file + '.meta'
                
                with open(encrypted_file, 'wb') as f:
                    f.write(encrypted['encrypted_data'])

                with open(meta_file, 'w') as f:
                    json.dump({
                        'iv': encrypted['iv'].hex(),
                        'encrypted_key': encrypted['encrypted_key'].hex(),
                        'signature_r': encrypted['signature'][0],
                        'signature_s': encrypted['signature'][1],
                        'rsa_public_key': encrypted['rsa_public_key'],
                        'schnorr_public_key': encrypted['schnorr_public_key']
                    }, f)
                
                print(f"\nEncryption successful!")
                print(f"Encrypted file: {encrypted_file}")
                print(f"Metadata file: {meta_file}")
                
            except Exception as e:
                print(f"Error during encryption: {str(e)}")
        
        elif choice == '2':
            try:
                encrypted_file = input("Enter path to encrypted file: ")
                meta_file = input("Enter path to metadata file: ")
                output_file = input("Enter path for decrypted output: ")
                
                # Read encrypted data and metadata
                with open(encrypted_file, 'rb') as f:
                    encrypted_data = f.read()
                
                # Read full metadata as JSON
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)
                
                package = {
                    'encrypted_data': encrypted_data,
                    'iv': bytes.fromhex(metadata['iv']),
                    'encrypted_key': bytes.fromhex(metadata['encrypted_key']),
                    'signature': (metadata['signature_r'], metadata['signature_s']),
                    'rsa_public_key': metadata['rsa_public_key'],
                    'schnorr_public_key': metadata['schnorr_public_key']
                    }
                
                # Decrypt and save
                decrypted_data = secure_system.decrypt_sound_file(package)
                
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                
                print(f"\nDecryption successful!")
                print(f"Decrypted file: {output_file}")
                
            except Exception as e:
                print(f"Error during decryption: {str(e)}")
        
        elif choice == '3':
            # Show stored public keys
            print("\nStored Public Keys:")
            print("RSA Public Key:")
            with open(secure_system.key_manager.rsa_public_file, 'r') as f:
                print(json.load(f))
            print("\nSchnorr Public Key:")
            with open(secure_system.key_manager.schnorr_public_file, 'r') as f:
                print(json.load(f))
        
        elif choice == '4':
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()