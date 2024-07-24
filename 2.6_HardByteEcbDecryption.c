#include "aes_ciphers.h"
#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BLOCK_SIZE 16

int findPrefixLen(size_t* prefixLength, size_t* secretLen, size_t blockLen, size_t prefixStringLen);
int EcbOracleTwo(const uint8_t* plaintext, size_t plaintextLen, uint8_t** ciphertext, size_t* cipherLen);
int findBlocksize2(size_t* blocksize, size_t* secretLen);
int findSecretString2(uint8_t* secretString, size_t secretLen, size_t blockLen, size_t prefixLen);
int findDifferentBlock(const uint8_t* cipherA, const uint8_t* cipherB, size_t cipherLen, size_t* blockNum);

uint8_t key[BLOCK_SIZE];
uint8_t* prefix;
size_t prefixLen;

int main()
{
    // Generate a random key
    if (RandomAesText(key, BLOCK_SIZE) != 0) {
        printf("Error: Random Aes Text for the key\n");
        return -1;
    }

    int minPrefix = 1;
    int maxPrefix = 32;

    uint8_t randomNum[] = {0};
    if (getentropy(randomNum, 1) == -1) {
        printf("Error: Get entopy\n");
        return 1;
    }

    prefixLen = (randomNum[0] % (maxPrefix - minPrefix + 1)) + minPrefix;
    printf("Real prefix length: %lu\n\n", prefixLen);

    prefix = (uint8_t*)malloc(prefixLen);
    if (getentropy(prefix, prefixLen) == -1) {
        printf("Error: Get entopy\n");
        return 1;
    }

    size_t blockSize = 0;
    size_t prefixAndStringLen;

    // Find the block size and secret string length using many calls to the Oracle
    if (findBlocksize2(&blockSize, &prefixAndStringLen) != 0) {
        printf("Error: Find block size\n");
        return 1;
    }

    printf("Blocksize: %lu\n", blockSize);
    printf("Secret String and Prefix length: %lu\n", prefixAndStringLen);

    size_t prefixLength = 0;
    size_t secretLen = 0;
    if (findPrefixLen(&prefixLength, &secretLen, blockSize, prefixAndStringLen) != 0) {
        printf("Error: Find Prefix length\n");
        return 1;
    }

    printf("Prefix length: %lu\n", prefixLength);
    printf("Secret String length: %lu\n", secretLen);

    uint8_t secretString[secretLen];
    memset(secretString, 0, secretLen);

    // Find the secret given its length and by repeated calls to the oracle function
    if (findSecretString2(secretString, secretLen, blockSize, prefixLen) != 0) {
        printf("Error: Find secret string");
        return 1;
    }

    printBytes(secretString, secretLen);
}

int findPrefixLen(size_t* prefixLength, size_t* secretLen, size_t blockLen, size_t prefixStringLen)
{
    if (prefixLength == NULL || secretLen == NULL) {
        return 1;
    }

    if (blockLen == 0 || blockLen >= SIZE_MAX) {
        printf("Error: Block length is invalid\n");
        return 1;
    }

    // Necessary variables
    uint8_t* cipherA = NULL;
    uint8_t* cipherB = NULL;
    size_t cipherLen = 0;
    size_t newBlockIndex = 0;
    size_t index = 1;
    uint8_t letter[] = "A";
    uint8_t letter2[] = "B";

    if (EcbOracleTwo(letter, 1, &cipherA, &cipherLen) != 0) {
        printf("Error: ECB Oracle call 1\n");
        return 1;
    }

    if (EcbOracleTwo(letter2, 1, &cipherB, &cipherLen) != 0) {
        printf("Error: ECB Oracle call 2\n");
        free(cipherA);
        return 1;
    }

    size_t difBlockIndex = 0;
    if (findDifferentBlock(cipherA, cipherB, cipherLen, &difBlockIndex) != 0) {
        printf("Error: Find different block\n");
        free(cipherA);
        free(cipherB);
        return 1;
    }
    free(cipherA);
    free(cipherB);
    cipherA = NULL;
    cipherB = NULL;

    newBlockIndex = difBlockIndex;

    while (newBlockIndex == difBlockIndex) {
        index++;
        uint8_t inputA[index];
        uint8_t inputB[index];
        for (size_t i = 0; i < index - 1; i++) {
            inputA[i] = (uint8_t)'A';
            inputB[i] = (uint8_t)'A';
        }
        inputA[index - 1] = (uint8_t)'A';
        inputB[index - 1] = (uint8_t)'B';

        if (EcbOracleTwo(inputA, index, &cipherA, &cipherLen) != 0) {
            printf("Error: ECB Oracle call 3\n");
            return 1;
        }

        if (EcbOracleTwo(inputB, index, &cipherB, &cipherLen) != 0) {
            free(cipherA);
            return 1;
        }

        if (findDifferentBlock(cipherA, cipherB, cipherLen, &newBlockIndex) != 0) {
            printf("Error: Find different block\n");
            free(cipherA);
            free(cipherB);
            return 1;
        }
        free(cipherA);
        free(cipherB);
        cipherA = NULL;
        cipherB = NULL;
    }

    if (index > difBlockIndex * blockLen) {
        printf("Error: Error in index for finding prefix length\n");
        return 1;
    }

    *prefixLength = ((difBlockIndex + 1) * blockLen) - (index - 1);
    *secretLen = prefixStringLen - *prefixLength;

    return 0;
}

int EcbOracleTwo(const uint8_t* plaintext, size_t plaintextLen, uint8_t** ciphertext, size_t* cipherLen)
{

    if (plaintext == NULL || ciphertext == NULL || cipherLen == NULL) {
        return 1;
    }

    // The secret string in base64
    char addString[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIH"
                       "NheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    size_t base64Len = strlen(addString);

    if (base64Len < 4 || base64Len >= SIZE_MAX) {
        printf("Error: Secret string base64 length invalid\n");
        return 1;
    }

    size_t bytesLen = (base64Len * 3 / 4) - (addString[base64Len - 1] == '=') - (addString[base64Len - 2] == '=');

    if (bytesLen < 3 || bytesLen >= SIZE_MAX) {
        printf("Error: Secret string byte length invalid\n");
        return 1;
    }

    uint8_t addBytes[bytesLen];
    memset(addBytes, 0, bytesLen);

    // Error check on the input length
    if (plaintextLen == 0 || plaintextLen > SIZE_MAX - bytesLen - prefixLen - BLOCK_SIZE - 1) {
        printf("Error: Plaintext input is too long\n");
        return 1;
    }

    // Convert to bytes from base64
    if (base64ToBinary(addString, addBytes, bytesLen) != 0) {
        printf("Error: Base64 to Binary\n");
        return 1;
    }

    // Create the plaintext with the secret string appended to the end
    size_t longPlaintextLen = prefixLen + plaintextLen + bytesLen;
    uint8_t longPlaintext[longPlaintextLen];
    memset(longPlaintext, 0, longPlaintextLen);
    memcpy(longPlaintext, prefix, prefixLen);
    memcpy(longPlaintext + prefixLen, plaintext, plaintextLen);
    memcpy(longPlaintext + prefixLen + plaintextLen, addBytes, bytesLen);

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
    if (encryptECB(paddedPlaintext, paddedLen, key, *ciphertext, cipherLen) != 0) {
        printf("Error: Encrypt ECB\n");
        free(*ciphertext);
        return -1;
    }

    return 0;
}

int findDifferentBlock(const uint8_t* cipherA, const uint8_t* cipherB, size_t cipherLen, size_t* blockNum)
{
    if (cipherA == NULL || cipherB == NULL || blockNum == NULL) {
        return 1;
    }

    if (cipherLen % BLOCK_SIZE != 0) {
        printf("Error: Cipher length must be a multiple of the block size\n");
        return 1;
    }

    for (size_t block = 0; block < cipherLen / BLOCK_SIZE; block++) {
        if (memcmp(cipherA + (block * BLOCK_SIZE), cipherB + (block * BLOCK_SIZE), BLOCK_SIZE) != 0) {
            *blockNum = block;
            return 0;
        }
    }

    printf("Error: Could not find differing block\n");
    return 1;
}

int findBlocksize2(size_t* blocksize, size_t* secretLen)
{

    if (blocksize == NULL || secretLen == NULL) {
        return 1;
    }

    // Necessary variables
    uint8_t* cipher = NULL;
    size_t cipherLen = 0;
    size_t newLen = 0;
    size_t index = 1;
    uint8_t letter[] = "A";

    // Finds the cipher length when the user inputs a string of 1 character
    if (EcbOracleTwo(letter, 1, &cipher, &cipherLen) != 0) {
        printf("Error: ECB Oracle call 1\n");
        return 1;
    }
    free(cipher);
    cipher = NULL;

    newLen = cipherLen;

    // Keep passing in additional letters until the size of the ciphertext increases (by a blocksize)
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
        if (EcbOracleTwo(bytes, index, &cipher, &newLen) != 0) {
            printf("Error: ECB Oracle call 2\n");
            return 1;
        }
        free(cipher);
        cipher = NULL;
    }
    *blocksize = newLen - cipherLen; // The block length is just whatever the increase in cipher length was
    *secretLen = cipherLen - index;  // Can remove the amount of letters we added to find the secret length

    return 0;
}

int findSecretString2(uint8_t* secretString, size_t secretLen, size_t blockLen, size_t prefixLen)
{

    if (secretString == NULL) {
        return 1;
    }

    if (blockLen == 0 || blockLen >= SIZE_MAX) {
        printf("Error: Block length is invalid\n");
        return 1;
    }

    size_t blocksForPrefix = (prefixLen / blockLen) + 1;

    if (blocksForPrefix < 1 || blocksForPrefix >= (SIZE_MAX / blockLen)) {
        printf("Error: Blocks for prefix value is invalid\n");
        return 1;
    }

    size_t addForPrefix = blockLen - (prefixLen - ((blocksForPrefix - 1) * blockLen));

    for (size_t letter = 0; letter < secretLen; letter++) {

        size_t blockNum = letter / blockLen;

        // This is the input size we need to put the letter in question in the last position in a block
        size_t inputSize = blockLen - (letter - (blockNum * blockLen)) - 1 + (addForPrefix);

        if (inputSize == 0 || inputSize >= SIZE_MAX) {
            printf("Error: Input size is invalid\n");
            return 1;
        }

        uint8_t firstInput[inputSize];
        memset(firstInput, 'A', inputSize);

        uint8_t* cipher = NULL;
        size_t cipherLen = 0;

        // Call Oracle with our specific length input
        if (EcbOracleTwo(firstInput, inputSize, &cipher, &cipherLen) != 0) {
            printf("Error: ECB Oracle call 1\n");
            return 1;
        }

        // Store the block of ciphertext that contains the letter we are finding
        uint8_t blockToFind[blockLen];
        memcpy(blockToFind, cipher + ((blockNum + blocksForPrefix) * blockLen), blockLen);

        free(cipher);
        cipher = NULL;

        // Creates a new input that includes the characters from our first input and all the letters we have found so far
        size_t newInputSize = ((blockNum + 1) * blockLen) + addForPrefix;

        if (newInputSize < 1 || newInputSize > SIZE_MAX) {
            printf("Error: New Input Size is invalid\n");
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

            if (EcbOracleTwo(input, newInputSize, &cipher, &cipherLen) != 0) {
                printf("Error: ECB Oracle call 2\n");
                return 1;
            }

            // If the ciphertexts match, then the letter we tried is the one in the secret string we are looking for
            if (memcmp(blockToFind, cipher + ((blockNum + blocksForPrefix) * blockLen), blockLen) == 0) {
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