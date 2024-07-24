#include "aes_ciphers.h"
#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BLOCK_SIZE 16

int PaddingValidation(const uint8_t* plaintext, size_t plaintextLen, uint8_t** unpaddedPt, size_t* unpaddedLen);

int main()
{

    char test[] = "ICE ICE BABY\x01\x02\x03\x04";

    uint8_t* plaintext = NULL;
    size_t plaintextLen = 0;

    if (PaddingValidation((uint8_t*)test, strlen(test), &plaintext, &plaintextLen)) {
        printf("Error: Padding Validation\n");
        return 1;
    }

    printBytes(plaintext, plaintextLen);
    free(plaintext);

    return 0;
}

int PaddingValidation(const uint8_t* plaintext, size_t plaintextLen, uint8_t** unpaddedPt, size_t* unpaddedLen)
{

    // Argument checks
    if (plaintext == NULL || unpaddedPt == NULL || unpaddedLen == NULL) {
        return 1;
    }

    if (plaintextLen < 1 || plaintextLen >= SIZE_MAX - 1 - BLOCK_SIZE) {
        printf("Error: Plaintext length is invalid\n");
        return 1;
    }

    size_t pad = plaintext[plaintextLen - 1];
    if (pad < 1 || pad > BLOCK_SIZE) {
        printf("Error: Padding in invalid\n");
        return 1;
    }
    for (size_t i = 0; i < pad; i++) {
        if (plaintext[plaintextLen - 1 - i] != pad) {
            printf("Error: Padding in invalid\n");
            return -1;
        }
    }

    *unpaddedLen = plaintextLen - pad;
    *unpaddedPt = (uint8_t*)malloc(*unpaddedLen);
    if (*unpaddedPt == NULL) {
        printf("Error: Could not allocate memory\n");
        return 1;
    }

    if (removePkcsPadding(plaintext, plaintextLen, pad, *unpaddedPt) != 0) {
        printf("Error: Remove PKCS Padding\n");
        free(*unpaddedPt);
        return 1;
    }

    return 0;
}