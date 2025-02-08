from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import os
import json

class TokenCipher:
    def __init__(self, key: str):
        """
        Inicializa a classe TokenCipher com uma chave em formato hexadecimal.
        A chave deve representar 32 bytes (AES-256).
        """
        # Converte a chave de hexadecimal para bytes e valida seu tamanho
        key_bytes = bytes.fromhex(key)
        if len(key_bytes) != 32:
            raise ValueError(f"A chave deve ter 32 bytes e agora contem {len(key_bytes)} bytes")
        self.key = key_bytes
        self.iv_length = 16  # Tamanho da IV em bytes

    @staticmethod
    def base64url_encode(data: bytes) -> str:
        """Codifica bytes no formato base64url sem padding."""
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

    @staticmethod
    def base64url_decode(data: str) -> bytes:
        """Decodifica uma string codificada em base64url (adicionando padding quando necessário)."""
        padding = '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)

    def encrypt(self, data) -> str:
        """
        Criptografa a serialização JSON de `data` utilizando AES-CBC com padding PKCS7.
        Retorna uma string codificada em base64url contendo a IV e o ciphertext.
        """
        # Gera uma IV aleatória
        iv = os.urandom(self.iv_length)
        
        # Cria o objeto cipher usando AES em modo CBC
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Converte os dados para JSON e, em seguida, para bytes
        plaintext = json.dumps(data).encode('utf-8')
        
        # Aplica padding PKCS7
        padded_plaintext = pad(plaintext, AES.block_size)
        
        # Criptografa o texto com padding
        encrypted = cipher.encrypt(padded_plaintext)
        
        # Codifica a IV e o ciphertext em base64 padrão
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
        
        # Combina a IV e o ciphertext com um separador de dois pontos
        combined = f"{iv_b64}:{encrypted_b64}"
        
        # Codifica a string combinada em base64url
        token = self.base64url_encode(combined.encode('utf-8'))
        return token

    def decrypt(self, token: str) -> dict:
        """
        Descriptografa o token produzido por encrypt() e retorna os dados originais (a partir do JSON).
        Se ocorrer qualquer erro durante o processo, retorna None.
        """
        if not token:
            return None
        try:
            # Decodifica o token de base64url para uma string UTF-8.
            decoded = self.base64url_decode(token).decode('utf-8')
            # Separa a string pelo separador ":" para obter a IV e o ciphertext.
            parts = decoded.split(":", 1)
            if len(parts) != 2:
                return None
            iv_b64, encrypted_b64 = parts
            iv = base64.b64decode(iv_b64)
            encrypted = base64.b64decode(encrypted_b64)
            
            # Cria o objeto cipher para a decriptografia
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(encrypted)
            # Remove o padding PKCS7
            plaintext = unpad(padded_plaintext, AES.block_size)
            # Converte o JSON de volta para um objeto Python
            data = json.loads(plaintext.decode('utf-8'))
            return data
        except Exception:
            return None
