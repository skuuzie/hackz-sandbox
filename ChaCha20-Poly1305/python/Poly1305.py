from math import ceil

def clamp(r: bytearray):
    r[3] &= 15
    r[7] &= 15
    r[11] &= 15
    r[15] &= 15
    r[4] &= 252
    r[8] &= 252
    r[12] &= 252

def poly1305_mac(message: bytes, key: bytes):

    if len(key) != 32:
        raise ValueError("Key length must be 256-bit (32 bytes)")

    r = bytearray(key[:16])
    s = bytearray(key[16:])
    clamp(r)

    r = int.from_bytes(r, "little")
    s = int.from_bytes(s, "little")

    a = 0
    p = (1 << 130) - 5

    for i in range(ceil(len(message) / 16)):
        n = int.from_bytes(message[i*16:(i+1) * 16] + b'\x01', "little")
        a += n
        a = (r * a) % p

    a += s

    return a.to_bytes(17, "little")[:-1]