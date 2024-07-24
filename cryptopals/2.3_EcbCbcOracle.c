#include "aes_ciphers.h"
#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int EncryptionOracle(const uint8_t* plaintext, size_t plaintextLen, uint8_t** ciphertext, size_t* cipherLen);
int GuessCipher(const uint8_t* ciphertext, size_t cipherLen, int* ecbUsed);

int main()
{

    size_t plaintextLen = 0;

    // Find the file length
    if (findFileLength("2.3_Plaintext.txt", &plaintextLen) != 0) {
        printf("Error: Find file length\n");
        return 1;
    }

    // Check the file is not too long
    if (plaintextLen == 0 || plaintextLen > SIZE_MAX - 1) {
        printf("Error: Base64 length is invalid\n");
        return 1;
    }

    char plaintext[plaintextLen + 1];

    // Read the file
    if (readLongFile("2.3_Plaintext.txt", plaintext, plaintextLen) != 0) {
        printf("Error: Read long string\n");
        return 1;
    }

    uint8_t* ciphertext = NULL;
    size_t cipherLen = 0;
    int ecbUsed = 0;

    // Run 20 tests of the guessing function
    for (int i = 0; i < 20; i++) {
        printf("Round %d:\n", i);

        // Call the oracle, which will use ECB or CBC at random
        if (EncryptionOracle((uint8_t*)plaintext, plaintextLen, &ciphertext, &cipherLen) != 0) {
            printf("Error: ECB or CBC Encrypt\n");
            if (ciphertext != NULL) {
                free(ciphertext);
            }
            return 1;
        }

        // Using the ciphertext, predict whether ECB or CBC was used
        if (GuessCipher(ciphertext, cipherLen, &ecbUsed) != 0) {
            printf("Error: Guess cipher\n");
            if (ciphertext != NULL) {
                free(ciphertext);
            }
            return 1;
        }

        free(ciphertext);
        ciphertext = NULL;
    }
    return 0;
}

int EncryptionOracle(const uint8_t* plaintext, size_t plaintextLen, uint8_t** ciphertext, size_t* cipherLen)
{

    if (plaintext == NULL || ciphertext == NULL || cipherLen == NULL) {
        return 1;
    }

    if (plaintextLen == 0 || plaintextLen > SIZE_MAX - 21 - 16) {
        printf("Size of file too large\n");
        return 1;
    }

    int blockLen = 16;
    uint8_t key[blockLen];

    // Generate a random key
    if (RandomAesText(key, blockLen) != 0) {
        printf("Error: Random Aes Text for the key\n");
        return -1;
    }

    // Generate 3 random numbers
    uint8_t randomNums[3];
    memset(randomNums, 0, 3);
    if (getentropy(randomNums, 3) == -1) {
        printf("Error: Get entropy\n");
        return 1;
    }

    // Random amount of bytes (5-10) added for the front and back of the input string
    int numBytesStart = 5 + (randomNums[0] % 6);
    int numBytesEnd = 5 + (randomNums[1] % 6);
    printf("Num at start: %d and Num at end: %d\n", numBytesStart, numBytesEnd);
    uint8_t bytesAtStart[numBytesStart];
    memset(bytesAtStart, 0, numBytesStart);
    uint8_t bytesAtEnd[numBytesEnd];
    memset(bytesAtEnd, 0, numBytesEnd);
    if (RandomAesText(bytesAtStart, (size_t)numBytesStart) != 0) {
        printf("Error: Random Aes Text for the bytes at start\n");
        return -1;
    }
    if (RandomAesText(bytesAtEnd, (size_t)numBytesEnd) != 0) {
        printf("Error: Random Aes Text for the bytes at end\n");
        return -1;
    }

    // Create the plaintext with the additional random bytes
    size_t longPlaintextLen = numBytesStart + plaintextLen + numBytesEnd;
    uint8_t longPlaintext[longPlaintextLen];
    memset(longPlaintext, 0, longPlaintextLen);
    memcpy(longPlaintext, bytesAtStart, numBytesStart);
    memcpy(longPlaintext + numBytesStart, plaintext, plaintextLen);
    memcpy(longPlaintext + numBytesStart + plaintextLen, bytesAtEnd, numBytesEnd);

    size_t pad = blockLen - (longPlaintextLen % blockLen); // How much do we need to pad
    size_t paddedLen = longPlaintextLen + pad;

    uint8_t paddedPlaintext[paddedLen];

    // Applies the padding
    if (PkcsPadding(longPlaintext, longPlaintextLen, blockLen, pad, paddedPlaintext) != 0) {
        printf("Error: PKCS Padding\n");
        return 1;
    }

    *ciphertext = (uint8_t*)malloc(sizeof(uint8_t) * paddedLen);
    if (*ciphertext == NULL) {
        printf("Error: Could not allocate memory\n");
        return 1;
    }

    // Choose ECB or CBC and perform the encryption
    if (randomNums[2] % 2 == 0) {
        if (encryptECB(paddedPlaintext, paddedLen, key, *ciphertext, cipherLen) != 0) {
            printf("Error: Encrypt ECB\n");
            return -1;
        }
        printf("Code: ECB was used\n");
    }
    else {
        uint8_t initVec[blockLen];
        memset(initVec, 0, blockLen);
        if (RandomAesText(initVec, blockLen) != 0) {
            printf("Error: Random Aes Text for the initVec\n");
            return -1;
        }
        if (CbcEncrypt(paddedPlaintext, paddedLen, key, initVec, *ciphertext, cipherLen)) {
            printf("Error: Decrypt CBC\n");
            return -1;
        }
        printf("Code: CBC was used\n");
    }

    return 0;
}

int GuessCipher(const uint8_t* ciphertext, size_t cipherLen, int* ecbUsed)
{
    if (ciphertext == NULL || ecbUsed == NULL) {
        return 1;
    }

    int verdict = 0;

    if (DetectEcbInLine(ciphertext, cipherLen, &verdict) != 0) {
        printf("Error: Detect ECB in line\n");
        return 1;
    }
    if (verdict == 1) {
        printf("Prediction: ECB mode was used\n");
        *ecbUsed = 1;
    }
    else {
        printf("Prediction: CBC was used\n");
        *ecbUsed = 0;
    }

    return 0;
}
