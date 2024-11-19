#include "chacha20.h"
#include <vector>
#include <iostream>

int main() {
    std::vector<uint8_t> key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    std::vector<uint8_t> iv = {0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0};
    int counter = 1;

    std::vector<uint8_t> data = {76, 97, 100, 105, 101, 115, 32, 97, 110, 100, 32, 71, 101, 110, 116, 108, 101, 109, 101, 110, 32, 111, 102, 32, 116, 104, 101, 32, 99, 108, 97, 115, 115, 32, 111, 102, 32, 39, 57, 57, 58, 32, 73, 102, 32, 73, 32, 99, 111, 117, 108, 100, 32, 111, 102, 102, 101, 114, 32, 121, 111, 117, 32, 111, 110, 108, 121, 32, 111, 110, 101, 32, 116, 105, 112, 32, 102, 111, 114, 32, 116, 104, 101, 32, 102, 117, 116, 117, 114, 101, 44, 32, 115, 117, 110, 115, 99, 114, 101, 101, 110, 32, 119, 111, 117, 108, 100, 32, 98, 101, 32, 105, 116, 46};

    auto enc = encrypt(key, iv, counter, data);

    for (int i = 0; i < enc.size(); i++) {
        printf("%02x", enc[i]);
    }
    printf("\n");

    auto dec = decrypt(key, iv, counter, enc);

    printf("%s\n", dec.data());

    return 0;
}