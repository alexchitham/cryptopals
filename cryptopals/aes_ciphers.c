#include "aes_ciphers.h"
#include <openssl/evp.h>

#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * Performs the binary XOR operation on two byte buffers and copies the output into a pre-defined buffer.
 *
 * @param binary1 Pointer to the first buffer of bytes
 * @param binary2 Pointer to the second buffer of bytes
 * @param outputXor Pointer to the buffer that will contain the output bytes
 * @param len Length of all the byte buffers
 *
 * @returns 0 on success, 1 if the any of the pointers are null
 */
static int binaryXOR2(const uint8_t* binary1, const uint8_t* binary2, uint8_t* outputXor, size_t len)
{
    if (binary1 == NULL || binary2 == NULL || outputXor == NULL) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        outputXor[i] = binary1[i] ^ binary2[i]; // XOR on each byte in the array
    }
    return 0;
}

int PkcsPadding(const uint8_t* msg, size_t msgLen, size_t blockLen, size_t pad, uint8_t* output)
{
    // Argument checks
    if (msg == NULL || blockLen <= 0 || output == NULL) {
        return 1;
    }

    // Copy the contents of message into padded array
    for (size_t i = 0; i < msgLen; i++) {
        output[i] = msg[i];
    }

    // Copy in the padded values in the gaps
    for (size_t j = 0; j < pad; j++) {
        output[msgLen + j] = (uint8_t)pad;
    }

    return 0;
}

int removePkcsPadding(const uint8_t* padInput, size_t paddedLength, size_t pad, uint8_t* output)
{
    // Argument checks
    if (padInput == NULL || output == NULL || paddedLength == 0) {
        return 1;
    }

    if (pad > UINT8_MAX) {
        printf("Error: Pad value is too large\n");
        return 1;
    }

    if ((uint8_t)pad != padInput[paddedLength - 1]) {
        return 1;
    }

    // Copies the plaintext up where the padding starts
    for (size_t i = 0; i < paddedLength - pad; i++) {
        output[i] = padInput[i];
    }

    return 0;
}

int encryptECB(const uint8_t* plaintext, size_t plaintextLen, const uint8_t* key, uint8_t* ciphertext, size_t* cipherLen)
{
    // Argument checks
    if (plaintext == NULL || key == NULL || ciphertext == NULL || cipherLen == NULL) {
        return 1;
    }

    int ret = 0;
    int newLen = 0;

    // Creates the context
    EVP_CIPHER_CTX* ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Error: EVP_CIPHER_CTX_new\n");
        return -1;
    }

    // Turn off automatic padding as we do that ourselves
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Initialise the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        printf("Error: EVP_DecryptInit_ex2\n");
        ret = -1;
        goto free_context;
    }

    // if (1 != EVP_EncryptInit_ex2(ctx, EVP_CIPHER_fetch(NULL, "AES-128-ECB", NULL), key, NULL, NULL)) {
    //     printf("Error: EVP_EncryptInit_ex2\n");
    //     return -1;
    // }

    // Length check
    if (plaintextLen >= INT_MAX) {
        printf("Error: Plaintext length invalid\n");
        ret = 1;
        goto free_context;
    }

    // Perform the encryption to obtain the plaintext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &newLen, plaintext, (int)plaintextLen)) {
        printf("Error: EVP_EncryptUpdate\n");
        ret = -1;
        goto free_context;
    }

    // Length check
    if (newLen < 0) {
        printf("Error: New length of plaintext is invalid\n");
        ret = 1;
        goto free_context;
    }

    // Set the length of the cipher
    *cipherLen = newLen;

    // Finalise the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + newLen, &newLen)) {
        printf("Error: EVP_EncryptFinal_ex\n");
        return -1;
    }

    // Add any additional length
    *cipherLen += (size_t)newLen;

free_context:
    // Cleaning up
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int decryptECB(const uint8_t* ciphertext, size_t cipherLen, const uint8_t* key, uint8_t* plaintext, size_t* plaintextLen)
{
    // Argument checks
    if (ciphertext == NULL || key == NULL || plaintext == NULL || plaintextLen == NULL) {
        return 1;
    }

    int ret = 0;
    int newLen = 0;

    // Creates the context
    EVP_CIPHER_CTX* ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Error: EVP_CIPHER_CTX_new\n");
        return -1;
    }

    // Turn off automatic padding as we do that ourselves
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Initialise the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        printf("Error: EVP_DecryptInit_ex2\n");
        ret = -1;
        goto free_context;
    }

    // if (1 != EVP_DecryptInit_ex2(ctx, EVP_CIPHER_fetch(NULL, "AES-128-ECB", NULL), key, NULL, NULL)) {
    //     printf("Error: EVP_DecryptInit_ex2\n");
    //     return -1;
    // }

    // Length check
    if (cipherLen >= INT_MAX) {
        printf("Error: Cipher length invalid\n");
        ret = 1;
        goto free_context;
    }

    // Perform the decryption to obtain the plaintext
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &newLen, ciphertext, (int)cipherLen)) {
        printf("Error: EVP_DecryptUpdate\n");
        ret = -1;
        goto free_context;
    }

    // Length check
    if (newLen < 0) {
        printf("Error: New length of plaintext is invalid\n");
        ret = 1;
        goto free_context;
    }

    // Set the length of the plaintext
    *plaintextLen = newLen;

    // Finalise the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + newLen, &newLen)) {
        printf("Error: EVP_DecryptFinal_ex\n");
        ret = -1;
        goto free_context;
    }

    // Add any additional length
    *plaintextLen += (size_t)newLen;

free_context:
    // Cleaning up
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int CbcEncrypt(const uint8_t* plaintext, size_t plaintextLen, const uint8_t* key, const uint8_t* initVec, uint8_t* ciphertext, size_t* cipherLen)
{
    // Argument checks
    if (plaintext == NULL || plaintextLen == 0 || key == NULL || initVec == NULL || ciphertext == NULL || cipherLen == NULL) {
        return 1;
    }

    if (plaintextLen == 0 || plaintextLen >= SIZE_MAX) {
        return 1;
    }

    size_t blockLen = 16;
    if (plaintextLen % blockLen != 0) {
        return 1;
    }

    // Relevant variables
    uint8_t ciphBlock[blockLen];
    memset(ciphBlock, 0, blockLen);
    uint8_t curBlock[blockLen];
    uint8_t xorBlock[blockLen];
    size_t newLen = 0;
    *cipherLen = 0;

    // Initiate the previous block as the initialisation vector
    uint8_t prevBlock[blockLen];
    for (size_t byte = 0; byte < blockLen; byte++) {
        prevBlock[byte] = initVec[byte];
    }

    // Iterate over each block in the plaintext
    for (size_t i = 0; i < plaintextLen / blockLen; i++) {

        // Copy the current block from the plaintext into its own buffer
        for (size_t byte = 0; byte < blockLen; byte++) {
            curBlock[byte] = plaintext[byte + (i * blockLen)];
        }

        // XOR the previous block and current block
        if (binaryXOR2(prevBlock, curBlock, xorBlock, blockLen) != 0) {
            printf("Error: Binary XOR\n");
            return -1;
        }

        // Encrypt the resulting XOR block using ECB mode
        if (encryptECB(xorBlock, blockLen, key, ciphBlock, &newLen) != 0) {
            printf("Error: Encrypt ECB\n");
            return -1;
        }
        *cipherLen += newLen; // Update the ciphertext length

        // The previous block becomes the ciphertext block we just encrypted
        // And copy the ciphertext block into the ciphertext buffer
        for (size_t j = 0; j < blockLen; j++) {
            prevBlock[j] = ciphBlock[j];
            ciphertext[j + (i * blockLen)] = ciphBlock[j];
        }
    }

    return 0;
}

int CbcDecrypt(const uint8_t* ciphertext, size_t cipherLen, const uint8_t* key, const uint8_t* initVec, uint8_t* plaintext, size_t* plaintextLen)
{
    // Argument checks
    if (ciphertext == NULL || key == NULL || initVec == NULL || plaintext == NULL || plaintextLen == NULL) {
        return 1;
    }

    if (cipherLen == 0 || cipherLen >= SIZE_MAX) {
        return 1;
    }

    size_t blockLen = 16;
    if (cipherLen % blockLen != 0) {
        return 1;
    }

    // Relevant variables
    uint8_t txtBlock[blockLen];
    uint8_t curBlock[blockLen];
    uint8_t xorBlock[blockLen];
    memset(xorBlock, 0, blockLen);
    size_t newLen = 0;
    *plaintextLen = 0;

    // Initiate the previous block as the initialisation vector
    uint8_t prevBlock[blockLen];
    for (size_t byte = 0; byte < blockLen; byte++) {
        prevBlock[byte] = initVec[byte];
    }

    // Iterate over each block in the ciphertext
    for (size_t i = 0; i < cipherLen / blockLen; i++) {

        // Copy the current block from the ciphertext into its own buffer
        for (size_t byte = 0; byte < blockLen; byte++) {
            curBlock[byte] = ciphertext[byte + (i * blockLen)];
        }

        // Decrypt the current ciphertext block
        if (decryptECB(curBlock, blockLen, key, xorBlock, &newLen) != 0) {
            printf("Error: Decrypt ECB\n");
            return -1;
        }
        *plaintextLen += newLen; // Update the plaintext length

        // XOR the decryption output with the previous block to get plaintext
        if (binaryXOR2(xorBlock, prevBlock, txtBlock, blockLen) != 0) {
            printf("Error: Binary XOR\n");
            return -1;
        }

        // Set the previous block to the ciphertext block we just decrypted
        // And copy the plaintext block into the plaintext buffer
        for (size_t j = 0; j < blockLen; j++) {
            prevBlock[j] = curBlock[j];
            plaintext[j + (i * blockLen)] = txtBlock[j];
        }
    }
    return 0;
}

int DetectEcbInLine(const uint8_t* cipher, size_t byteLen, int* verdict)
{
    // Argument checks
    if (cipher == NULL || verdict == NULL) {
        return 1;
    }

    if (byteLen == 0 || byteLen >= INT_MAX) {
        printf("Cipher length is invalid\n");
        return 1;
    }

    // Relevant variables
    int numBlocks = (int)byteLen / 16;
    int guess = 1;
    *verdict = 0;

    // For each block, compare it with all the blocks in front of it, which covers all combinations
    for (int i = 0; i < numBlocks - 1; i++) {
        for (int j = i + 1; j < numBlocks; j++) {

            // Assume they are equal blocks
            guess = 1;

            // Checking each byte in the block
            for (int bytes = 0; bytes < 16; bytes++) {
                if (cipher[bytes + (i * 16)] != cipher[bytes + (j * 16)]) {
                    guess = 0; // If one byte isn't the same, then they cannot be identical so break
                    break;
                }
            }

            // The blocks are identical so print the result
            if (guess == 1) {
                printf("Block %d and Block %d ", i + 1, j + 1);
                *verdict = 1; // If all bytes in two blocks are the same, print and report success
                return 0;
            }
        }
    }
    return 0;
}

int RandomAesText(uint8_t* text, size_t textSize)
{
    // Argument checks
    if (text == NULL) {
        return 1;
    }
    if (textSize == 0 || textSize > 256) {
        printf("Error: Text size is invalid\n");
        return 1;
    }

    // Puts random bytes in each element in the buffer
    if (getentropy(text, textSize) == -1) {
        printf("Error: Get entopy\n");
        return -1;
    }
    return 0;
}
