#include <stdint.h>
#include <iostream>
#include <vector>
#include <math.h>
#include <cstring>

#include "chacha20.h"

uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

uint32_t to_int32(int a, int b, int c, int d) {
    return ((a & 0xFF) << 24) |
           ((b & 0xFF) << 16) | 
           ((c & 0xFF) << 8)  |  
           (d & 0xFF);           
}

uint32_t to_int32_le(int a, int b, int c, int d) {
    return ((d & 0xFF) << 24) |
           ((c & 0xFF) << 16) | 
           ((b & 0xFF) << 8)  |  
           (a & 0xFF);           
}

void to_uint8_le(uint32_t packed, uint8_t* a, uint8_t* b, uint8_t* c, uint8_t* d) {
    *a = (packed >> 24) & 0xFF;
    *b = (packed >> 16) & 0xFF;
    *c = (packed >> 8) & 0xFF;
    *d = packed & 0xFF; 
}

void quarter_round(cc2_ctx* ctx, int _a, int _b, int _c, int _d) {
    uint32_t* a = &ctx->state[_a];
    uint32_t* b = &ctx->state[_b];
    uint32_t* c = &ctx->state[_c];
    uint32_t* d = &ctx->state[_d];

    *a = (*a + *b) & 0xFFFFFFFF;
    *d ^= *a;
    *d = rotl(*d, 16);

    *c = (*c + *d) & 0xFFFFFFFF;
    *b ^= *c;
    *b = rotl(*b, 12);
    
    *a = (*a + *b) & 0xFFFFFFFF;
    *d ^= *a;
    *d = rotl(*d, 8);

    *c = (*c + *d) & 0xFFFFFFFF;
    *b ^= *c;
    *b = rotl(*b, 7);
}

void add_state(cc2_ctx* init, cc2_ctx* rounded) {
    for (int i = 0; i < 16; i += 4) {
        init->state[i] = (init->state[i] + rounded->state[i]) & 0xFFFFFFFF;
        init->state[i+1] = (init->state[i+1] + rounded->state[i+1]) & 0xFFFFFFFF;
        init->state[i+2] = (init->state[i+2] + rounded->state[i+2]) & 0xFFFFFFFF;
        init->state[i+3] = (init->state[i+3] + rounded->state[i+3]) & 0xFFFFFFFF;
    }
}

std::vector<uint8_t> encrypt(std::vector<uint8_t>& key, std::vector<uint8_t>& nonce, int counter, std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> out;
    out.resize(plaintext.size());

    cc2_ctx _ctx;
    cc2_ctx* ctx = &_ctx;
    uint8_t* block = new unsigned char[64];

    srand(time(NULL));

    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    ctx->state[4] = to_int32_le(key[0], key[1], key[2], key[3]);
    ctx->state[5] = to_int32_le(key[4], key[5], key[6], key[7]);
    ctx->state[6] = to_int32_le(key[8], key[9], key[10], key[11]);
    ctx->state[7] = to_int32_le(key[12], key[13], key[14], key[15]);
    ctx->state[8] = to_int32_le(key[16], key[17], key[18], key[19]);
    ctx->state[9] = to_int32_le(key[20], key[21], key[22], key[23]);
    ctx->state[10] = to_int32_le(key[24], key[25], key[26], key[27]);
    ctx->state[11] = to_int32_le(key[28], key[29], key[30], key[31]);
    ctx->state[12] = to_int32_le(counter, 0, 0, 0);
    ctx->state[13] = to_int32_le(nonce[0], nonce[1], nonce[2], nonce[3]);
    ctx->state[14] = to_int32_le(nonce[4], nonce[5], nonce[6], nonce[7]);
    ctx->state[15] = to_int32_le(nonce[8], nonce[9], nonce[10], nonce[11]);

    int t = 0;
    for (int i = 0; i < ((double) plaintext.size() / (double) 64); i++) {
        cc2_ctx _working = _ctx;
        cc2_ctx *working = &_working;

        for (int i = 0; i < 10; i++) {
            quarter_round(working, 0, 4, 8, 12);
            quarter_round(working, 1, 5, 9, 13);
            quarter_round(working, 2, 6, 10, 14);
            quarter_round(working, 3, 7, 11, 15);
            quarter_round(working, 0, 5, 10, 15);
            quarter_round(working, 1, 6, 11, 12);
            quarter_round(working, 2, 7, 8, 13);
            quarter_round(working, 3, 4, 9, 14);
        }

        add_state(working, ctx);

        int j = 0;
        for (int k = 0; k < 64;) {
            to_uint8_le(working->state[j++], &block[k++], &block[k++], &block[k++], &block[k++]);
        }

        for (int l = 0; l < 64; l++) {
            if (t == out.size()) {
                return out;
            }
            out[t] = plaintext[t] ^ block[l];
            t++;
        }

        ctx->state[12] = to_int32_le(++counter, 0, 0, 0);
    }

    return out;
}

std::vector<uint8_t> decrypt(std::vector<uint8_t>& key, std::vector<uint8_t>& nonce, int counter, std::vector<uint8_t>& ciphertext) {
    return encrypt(key, nonce, counter, ciphertext); // stream cipher, encrypt == decrypt
}