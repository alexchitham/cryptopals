#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int RepeatingKeyXor(const uint8_t* plaintext, size_t txtLen, const char* key, char* hexCipher, size_t hexLen);

int main()
{

    // Defining the test input
    char test[] = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    size_t inputLen = strlen(test);
    uint8_t* input = (uint8_t*)test;

    // Length check on the input
    if (inputLen == 0 || inputLen >= (SIZE_MAX - 2) / 2) {
        printf("Error: Input length is invalid\n");
        return 1;
    }

    // Defines a buffer to store the result
    size_t hexLen = 2 * inputLen;
    char answer[hexLen + 1];

    // Performs the repeating key encryption
    if (RepeatingKeyXor(input, inputLen, "ICE", answer, hexLen) != 0) {
        return 1;
    }

    // Check the result
    printf("%s\n", answer);
    printf("%d\n", strcmp(answer, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b20"
                                  "27630c692b20283165286326302e27282f"));
    return 0;
}

int RepeatingKeyXor(const uint8_t* plaintext, size_t txtLen, const char* key, char* hexCipher, size_t hexLen)
{

    // Argument checks
    if (plaintext == NULL || key == NULL || hexCipher == NULL) {
        return 1;
    }

    if (txtLen == 0 || txtLen >= SIZE_MAX || hexLen == 0 || hexLen >= SIZE_MAX - 1) {
        printf("Error: Input lengths is invalid\n");
        return 1;
    }

    if (txtLen != (hexLen + 1) / 2) {
        return 1;
    }

    // Makes key same length as plaintext
    uint8_t longKey[txtLen];
    for (size_t i = 0; i < txtLen; i++) {
        longKey[i] = (uint8_t)key[i % strlen(key)];
    }

    // Encrypts and stores in the cipher buffer
    uint8_t cipher[txtLen];
    if (binaryXOR(plaintext, longKey, cipher, txtLen) != 0) {
        printf("Error: Binary XOR\n");
        return 1;
    }

    // Converts to Hex
    if (BytesToHex(cipher, txtLen, hexCipher, hexLen) != 0) {
        printf("Error: Bytes to Hex\n");
        return 1;
    }
    return 0;
}
