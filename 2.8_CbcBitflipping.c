#include "aes_ciphers.h"
#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BLOCK_SIZE 16

int CbcOracleEnc(const uint8_t* plaintext, size_t plaintextLen, uint8_t** ciphertext, size_t* cipherLen);
int AdminDetector(const uint8_t* ciphertext, size_t cipherLen, int* adminString);

uint8_t key[BLOCK_SIZE];
uint8_t initVec[BLOCK_SIZE];

int main()
{

    int ret = 0;

    // Generate a random key
    if (RandomAesText(key, BLOCK_SIZE) != 0) {
        printf("Error: Random Aes Text for the key\n");
        return -1;
    }
    memset(initVec, 0, BLOCK_SIZE);

    uint8_t input[2 * BLOCK_SIZE];
    memset(input, 'a', 2 * BLOCK_SIZE);

    uint8_t* cipher = NULL;
    size_t cipherLen = 0;

    int adminPresent = 0;

    if (CbcOracleEnc(input, 2 * BLOCK_SIZE, &cipher, &cipherLen) != 0) {
        printf("Error: CBC Oracle Encrypt\n");
        return 1;
    }

    uint8_t xorForBlock[BLOCK_SIZE];
    if (binaryXOR(input, (uint8_t*)"aaaa;admin=true;", xorForBlock, BLOCK_SIZE) != 0) {
        printf("Error: Binary XOR\n");
        ret = 1;
        goto free_cipher;
    }

    if (binaryXOR(cipher + (2 * BLOCK_SIZE), xorForBlock, cipher + (2 * BLOCK_SIZE), BLOCK_SIZE) != 0) {
        printf("Error: Binary XOR\n");
        ret = 1;
        goto free_cipher;
    }

    if (AdminDetector(cipher, cipherLen, &adminPresent) != 0) {
        printf("Error: Admin Detector\n");
        ret = 1;
        goto free_cipher;
    }

    printf("Admin Account, 1 means yes, 0 is no: %d\n", adminPresent);
free_cipher:
    free(cipher);

    return ret;
}

int CbcOracleEnc(const uint8_t* plaintext, size_t plaintextLen, uint8_t** ciphertext, size_t* cipherLen)
{

    // Argument checks
    if (plaintext == NULL || ciphertext == NULL || cipherLen == NULL) {
        return 1;
    }

    const char prefix[] = "comment1=cooking%20MCs;userdata=";
    size_t prefixLen = strlen(prefix);
    const char suffix[] = ";comment2=%20like%20a%20pound%20of%20bacon";
    size_t suffixLen = strlen(suffix);

    if (plaintextLen == 0 || plaintextLen >= SIZE_MAX / 3 || plaintextLen >= SIZE_MAX - prefixLen - suffixLen - BLOCK_SIZE) {
        printf("Error: Plaintext length is invalid\n");
        return 1;
    }

    size_t specialChars = 0;
    for (size_t i = 0; i < plaintextLen; i++) {
        if (plaintext[i] == '=' || plaintext[i] == ';') {
            specialChars++;
        }
    }
    size_t index = 0;
    size_t newLen = plaintextLen + (2 * specialChars);
    uint8_t newPt[newLen];
    for (size_t j = 0; j < plaintextLen; j++) {
        if (plaintext[j] == '=') {
            memcpy(newPt + index, "%3d", 3);
            index += 2;
        }
        else if (plaintext[j] == ';') {
            memcpy(newPt + index, "%3b", 3);
            index += 2;
        }
        else {
            newPt[index] = plaintext[j];
        }
        index++;
        if (index >= SIZE_MAX - 2) {
            printf("Error: Index overflow\n");
            return 1;
        }
    }

    size_t longPlaintextLen = prefixLen + newLen + suffixLen;
    uint8_t longPlaintext[longPlaintextLen];
    memcpy(longPlaintext, prefix, prefixLen);
    memcpy(longPlaintext + prefixLen, newPt, newLen);
    memcpy(longPlaintext + prefixLen + newLen, suffix, suffixLen);

    size_t pad = BLOCK_SIZE - (longPlaintextLen % BLOCK_SIZE); // How much do we need to pad
    size_t paddedLen = longPlaintextLen + pad;
    uint8_t paddedPlaintext[paddedLen];

    // Applies the padding
    if (PkcsPadding(longPlaintext, longPlaintextLen, BLOCK_SIZE, pad, paddedPlaintext) != 0) {
        printf("Error: PKCS Padding\n");
        return -1;
    }

    // Allocated sufficient memory
    *ciphertext = (uint8_t*)malloc(sizeof(uint8_t) * paddedLen);
    if (*ciphertext == NULL) {
        printf("Error: Could not allocate memory\n");
        return 1;
    }

    // Encrypts the string
    if (CbcEncrypt(paddedPlaintext, paddedLen, key, initVec, *ciphertext, cipherLen) != 0) {
        printf("Error: Encrypt ECB\n");
        free(*ciphertext);
        return -1;
    }

    return 0;
}

int AdminDetector(const uint8_t* ciphertext, size_t cipherLen, int* adminString)
{
    if (ciphertext == NULL || adminString == NULL) {
        return 1;
    }

    if (cipherLen == 0 || cipherLen >= SIZE_MAX) {
        printf("Error: Cipher length is invalid \n");
        return 1;
    }
    uint8_t plaintext[cipherLen];
    size_t plaintextLen;

    if (CbcDecrypt(ciphertext, cipherLen, key, initVec, plaintext, &plaintextLen) != 0) {
        printf("Error: CBC Decrypt\n");
        return 1;
    }

    printBytes(plaintext, plaintextLen);

    char searchString[] = ";admin=true;";

    if (plaintextLen < strlen(searchString)) {
        printf("Error: Plaintext is too short to contain the search string\n");
        return 1;
    }

    for (size_t i = 0; i < plaintextLen - strlen(searchString) + 1; i++) {

        if (memcmp((uint8_t*)searchString, plaintext + i, strlen(searchString)) == 0) {
            *adminString = 1;
            return 0;
        }
    }
    *adminString = 0;
    return 0;
}