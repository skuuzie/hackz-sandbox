from math import ceil

def __rotl(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def __quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = __rotl(d, 16)

    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = __rotl(b, 12)
    
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = __rotl(d, 8)

    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = __rotl(b, 7)

    return a, b, c, d

def __init_state(key: bytes, nonce: bytes, block: int) -> bytearray:
    state = b''

    state += b'apxe'
    state += b'3 dn'
    state += b'yb-2'
    state += b'k et'

    state += key[0:4][::-1]
    state += key[4:8][::-1]
    state += key[8:12][::-1]
    state += key[12:16][::-1]
    state += key[16:20][::-1]
    state += key[20:24][::-1]
    state += key[24:28][::-1]
    state += key[28:32][::-1]

    state += block.to_bytes(4)

    state += nonce[0:4][::-1]
    state += nonce[4:8][::-1]
    state += nonce[8:12][::-1]

    return bytearray(state)

def __quarter_round_state(state: bytearray, a: int, b: int, c: int, d: int) -> None:
    aa = int.from_bytes(state[a*4:(a+1)*4])
    bb = int.from_bytes(state[b*4:(b+1)*4])
    cc = int.from_bytes(state[c*4:(c+1)*4])
    dd = int.from_bytes(state[d*4:(d+1)*4])
    
    state[a*4:(a+1)*4], state[b*4:(b+1)*4], state[c*4:(c+1)*4], state[d*4:(d+1)*4] = [t.to_bytes(4) for t in __quarter_round(aa, bb, cc, dd)]

def __add_state(s1: bytearray, s2: bytearray) -> None:
    for i in range(0, 16):
        s1[i*4:i*4+4] = ((int.from_bytes(s1[i*4:i*4+4]) + int.from_bytes(s2[i*4:i*4+4])) & 0xFFFFFFFF).to_bytes(4)

def __serialize(state: bytearray) -> bytes:
    serialized = b''

    for i in range(0, 16):
        serialized += state[i*4:i*4+4][::-1]
    
    return serialized

def __chacha20_block(key, nonce, block) -> bytes:
    st = __init_state(key, nonce, block)
    _st = bytearray(bytes(st))

    for _ in range(10):
        __quarter_round_state(_st, 0, 4, 8, 12)
        __quarter_round_state(_st, 1, 5, 9, 13)
        __quarter_round_state(_st, 2, 6, 10, 14)
        __quarter_round_state(_st, 3, 7, 11, 15)
        __quarter_round_state(_st, 0, 5, 10, 15)
        __quarter_round_state(_st, 1, 6, 11, 12)
        __quarter_round_state(_st, 2, 7, 8, 13)
        __quarter_round_state(_st, 3, 4, 9, 14)

    __add_state(st, _st)

    return bytes(__serialize(st))

def encrypt(data: bytes, key: bytes, nonce: bytes, init_counter: int = 0) -> bytes:

    if init_counter > 0xffffffff:
        raise ValueError("Counter can't exceed 2**32 - 1 (4294967295)")

    if len(data) == 0:
        raise ValueError("Data can't be empty")

    if len(key) != 32:
        raise ValueError("Key length must be 256-bit (32 bytes)")
    
    if len(nonce) != 12:
        raise ValueError("Nonce/IV length must be 96-bit (12 bytes)")

    enc = bytearray(data)

    for i in range(ceil(len(data) / 64)):
        ks = __chacha20_block(key, nonce, init_counter + (i * 1))
        print(ks.hex())
        for j in range(64):
            if j + (64*i) == len(data):
                return bytes(enc)
            enc[j + (64*i)] ^= ks[j]

    return bytes(enc)

def decrypt(data: bytes, key: bytes, nonce: bytes, init_counter: int = 0) -> bytes:

    if init_counter > 0xffffffff:
        raise ValueError("Counter can't exceed 2**32 - 1 (4294967295)")

    if len(data) == 0:
        raise ValueError("Data can't be empty")

    if len(key) != 32:
        raise ValueError("Key length must be 256-bit (32 bytes)")
    
    if len(nonce) != 12:
        raise ValueError("Nonce/IV length must be 96-bit (12 bytes)")
    
    return encrypt(data, key, nonce, init_counter)