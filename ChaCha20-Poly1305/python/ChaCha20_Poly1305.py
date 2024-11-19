import ChaCha20
import Poly1305

from math import ceil

class AEAD:
    def __init__(self, txt: bytes, tag: bytes) -> None:
        self.data = txt
        self.tag = tag
    
def __pad16(data: bytes):
    if len(data) % 16 == 0:
        return data
    return data.ljust(ceil(len(data) / 16) * 16, b'\x00')

def aead_encrypt(plaintext: bytes, aad: bytes, key: bytes, iv: bytes, constant: bytes = b'\x00' * 4):
    if len(key) != 32:
        raise ValueError("Key length must be 256-bit (32 bytes)")
    
    if len(iv) not in (8, 12):
        raise ValueError("IV/Nonce length must be 8 or 12 bytes")
    
    if len(iv) == 8:
        iv = constant + iv
    
    otk = ChaCha20.__chacha20_block(key, iv, 0)
    ctx = ChaCha20.encrypt(plaintext, key, iv, 1)

    mac = __pad16(aad)
    mac += __pad16(ctx)
    mac += len(aad).to_bytes(8, "little")
    mac += len(ctx).to_bytes(8, "little")

    tag = Poly1305.poly1305_mac(mac, otk[:32])

    return AEAD(ctx, tag)

def aead_decrypt(ciphertext: bytes, tag: bytes, aad: bytes, key: bytes, iv: bytes, constant: bytes = b'\x00' * 4):
    if len(key) != 32:
        raise ValueError("Key length must be 256-bit (32 bytes)")
    
    if len(iv) not in (8, 12):
        raise ValueError("IV/Nonce length must be 8 or 12 bytes")
    
    if len(iv) == 8:
        iv = constant + iv

    otk = ChaCha20.__chacha20_block(key, iv, 0)
    ptx = ChaCha20.decrypt(ciphertext, key, iv, 1)

    mac = __pad16(aad)
    mac += __pad16(ciphertext)
    mac += len(aad).to_bytes(8, "little")
    mac += len(ciphertext).to_bytes(8, "little")

    if tag != Poly1305.poly1305_mac(mac, otk[:32]):
        raise ValueError("MAC Failure, message is not authentic.")
    
    return ptx