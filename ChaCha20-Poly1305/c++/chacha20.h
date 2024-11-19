#include <stdint.h>
#include <vector>

struct cc2_ctx {
    uint32_t state[16];
};

// better return by value or reference?
std::vector<uint8_t> encrypt(std::vector<uint8_t>& key, std::vector<uint8_t>& nonce, int counter, std::vector<uint8_t>& plaintext);
std::vector<uint8_t> decrypt(std::vector<uint8_t>& key, std::vector<uint8_t>& nonce, int counter, std::vector<uint8_t>& ciphertext);