#include "aes_ciphers.h"
#include "core_functions.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int EcbOracle(const uint8_t* plaintext, size_t plaintextLen, uint8_t** ciphertext, size_t* cipherLen, const uint8_t* key);
int findBlocksize(size_t* blocksize, size_t* secretLen, const uint8_t* key);
int findSecretString(uint8_t* secretString, size_t secretLen, const uint8_t* key, size_t blockLen);

int main()
{

    size_t blockLen = 16;
    uint8_t key[blockLen];

    // Create the random key
    if (RandomAesText(key, blockLen) != 0) {
        printf("Error: Random Aes Text for the key\n");
        return 1;
    }

    size_t blockSize = 0;
    size_t secretStringLen;

    // Find the block size and secret string length using many calls to the Oracle
    if (findBlocksize(&blockSize, &secretStringLen, key) != 0) {
        printf("Error: Find block size\n");
        return 1;
    }

    printf("Blocksize: %lu\n", blockSize);
    printf("Secret String length: %lu\n", secretStringLen);
    printf("\n\n");

    if (secretStringLen == 0 || secretStringLen > SIZE_MAX) {
        printf("Size of secret string is too large\n");
        return 1;
    }

    uint8_t secretString[secretStringLen];
    memset(secretString, 0, secretStringLen);

    // Find the secret given its length and by repeated calls to the oracle function
    if (findSecretString(secretString, secretStringLen, key, blockSize) != 0) {
        printf("Error: Find secret string");
        return 1;
    }

    printBytes(secretString, secretStringLen);

    return 0;
}

int EcbOracle(const uint8_t* plaintext, size_t plaintextLen, uint8_t** ciphertext, size_t* cipherLen, const uint8_t* key)
{

    if (plaintext == NULL || ciphertext == NULL || cipherLen == NULL || key == NULL) {
        return 1;
    }

    size_t blockLen = 16;

    // The secret string in base64
    char addString[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIH"
                       "NheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    size_t base64Len = strlen(addString);

    if (base64Len < 4 || base64Len >= SIZE_MAX) {
        printf("Error: Secret string base64 length invalid\n");
        return 1;
    }

    size_t bytesLen = (base64Len * 3 / 4) - (addString[base64Len - 1] == '=') - (addString[base64Len - 2] == '=');

    if (bytesLen < 3 || bytesLen >= SIZE_MAX - blockLen) {
        printf("Error: Secret string byte length invalid\n");
        return 1;
    }

    uint8_t addBytes[bytesLen];
    memset(addBytes, 0, bytesLen);

    // Error check on the input length
    if (plaintextLen == 0 || plaintextLen >= SIZE_MAX - bytesLen - blockLen) {
        printf("Error: Plaintext input is invalid\n");
        return 1;
    }

    // Convert to bytes from base64
    if (base64ToBinary(addString, addBytes, bytesLen) != 0) {
        printf("Error: Base64 to Binary\n");
        return 1;
    }

    // Create the plaintext with the secret string appended to the end
    size_t longPlaintextLen = plaintextLen + bytesLen;
    uint8_t longPlaintext[longPlaintextLen];
    memset(longPlaintext, 0, longPlaintextLen);
    memcpy(longPlaintext, plaintext, plaintextLen);
    memcpy(longPlaintext + plaintextLen, addBytes, bytesLen);

    size_t pad = blockLen - (longPlaintextLen % blockLen); // How much do we need to pad
    size_t paddedLen = longPlaintextLen + pad;
    uint8_t paddedPlaintext[paddedLen];

    // Applies the padding
    if (PkcsPadding(longPlaintext, longPlaintextLen, blockLen, pad, paddedPlaintext) != 0) {
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
    if (encryptECB(paddedPlaintext, paddedLen, key, *ciphertext, cipherLen) != 0) {
        printf("Error: Encrypt ECB\n");
        return -1;
    }

    return 0;
}

int findBlocksize(size_t* blocksize, size_t* secretLen, const uint8_t* key)
{

    if (blocksize == NULL || secretLen == NULL || key == NULL) {
        return 1;
    }

    // Necessary variables
    uint8_t* cipher = NULL;
    size_t cipherLen = 0;
    size_t newLen = 0;
    size_t index = 1;
    uint8_t letter[] = "A";

    // Finds the cipher length when the user inputs a string of 1 character
    if (EcbOracle(letter, 1, &cipher, &cipherLen, key) != 0) {
        if (cipher != NULL) {
            free(cipher);
            cipher = NULL;
        }
        return 1;
    }
    free(cipher);
    cipher = NULL;

    newLen = cipherLen;

    // Keep passing in additional letters until the si|| base)ze of the ciphertext increases (by a blocksize)
    while (newLen == cipherLen) {

        if (index >= SIZE_MAX - 1) {
            printf("Error: Index is too large\n");
            return 1;
        }

        index++;
        uint8_t bytes[index];
        for (size_t i = 0; i < index; i++) {
            bytes[i] = (uint8_t)'A';
        }

        // Call the Oracle again with an input of more letters than before
        if (EcbOracle(bytes, index, &cipher, &newLen, key) != 0) {
            if (cipher != NULL) {
                free(cipher);
                cipher = NULL;
            }
            return 1;
        }
        free(cipher);
        cipher = NULL;
    }
    *blocksize = newLen - cipherLen; // The block length is just whatever the increase in cipher length was
    *secretLen = cipherLen - index;  // Can remove the amount of letters we added to find the secret length

    return 0;
}

int findSecretString(uint8_t* secretString, size_t secretLen, const uint8_t* key, size_t blockLen)
{

    if (secretString == NULL || key == NULL) {
        return 1;
    }

    if (blockLen == 0 || blockLen > SIZE_MAX - 1) {
        printf("Error: Block length is invalid\n");
        return 1;
    }

    // For (index 0) letter 1 -----> inputsize 15     +1 second time round
    // For (index 1) letter 2 -----> inputsize 14     +1 second time round to discover letter
    // For (index 2) letter 3 -----> inputsize 13
    // ............
    // For (index 15) letter 16 ---> inputsize 0

    // For (index 16) letter 17 ---> inputsize 15     but now look at second byte in the ciphertext    letter 32 (index 31) in the output
    // For (index 17) letter 18 ---> inputsize 14
    // For (index 18) letter 19 ---> inputsize 13

    // Loop for every letter in the secret string we need to find
    for (size_t letter = 0; letter < secretLen; letter++) {

        size_t blockNum = letter / blockLen;

        // This is the input size we need to put the letter in question in the last position in a block
        size_t inputSize = blockLen - (letter - (blockNum * blockLen)) - 1;

        if (inputSize == 0 || inputSize >= SIZE_MAX) {
            printf("Error: Input size invalid\n");
            return 1;
        }

        uint8_t firstInput[inputSize];
        memset(firstInput, 'A', inputSize);

        uint8_t* cipher = NULL;
        size_t cipherLen = 0;

        // Call Oracle with our specific length input
        if (EcbOracle(firstInput, inputSize, &cipher, &cipherLen, key) != 0) {
            if (cipher != NULL) {
                free(cipher);
                cipher = NULL;
            }
            return 1;
        }

        // Store the block of ciphertext that contains the letter we are finding
        uint8_t blockToFind[blockLen];
        memcpy(blockToFind, cipher + (blockNum * blockLen), blockLen);

        free(cipher);
        cipher = NULL;

        // Creates a new input that includes the characters from our first input and all the letters we have found so far
        size_t newInputSize = (blockNum + 1) * blockLen;

        if (newInputSize < 1 || newInputSize >= SIZE_MAX) {
            printf("Error: New input size is invalid\n");
            return 1;
        }

        uint8_t input[newInputSize];
        memcpy(input, firstInput, inputSize);
        for (size_t i = inputSize; i < newInputSize - 1; i++) {
            input[i] = secretString[i - inputSize];
        }

        // Test every possible character, putting in the last spot in the array and comparing it the block of ciphertext we are trying to replicate
        for (size_t posLet = 0; posLet <= UINT8_MAX; posLet++) {

            input[newInputSize - 1] = posLet;

            if (EcbOracle(input, newInputSize, &cipher, &cipherLen, key) != 0) {
                if (cipher != NULL) {
                    free(cipher);
                    cipher = NULL;
                }
                return 1;
            }

            // If the ciphertexts match, then the letter we tried is the one in the secret string we are looking for
            if (memcmp(blockToFind, cipher + (blockNum * blockLen), blockLen) == 0) {
                secretString[letter] = posLet;
                free(cipher);
                cipher = NULL;
                break;
            }
            free(cipher);
            cipher = NULL;
        }
    }

    return 0;
}