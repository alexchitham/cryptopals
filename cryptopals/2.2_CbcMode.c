#include "aes_ciphers.h"
#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 16

int main()
{

    size_t base64Len = 0;

    // Find the length of the file
    if (findFileLength("2.2_Cipher.txt", &base64Len) != 0) {
        printf("Error: Find file length\n");
        return 1;
    }

    // Check the file is not too long
    if (base64Len <= 3 || base64Len > SIZE_MAX - 1 || base64Len % 4 != 0) {
        printf("Error: Base64 length is invalid\n");
        return 1;
    }

    // Should be a malloc when it is 'user-defines' input, as easier to error out if it's too long
    char base64String[base64Len + 1]; // Define the string that will store file contents

    // Read the file
    if (readLongFile("2.2_Cipher.txt", base64String, base64Len) != 0) {
        printf("Error: Read long string\n");
        return 1;
    }

    // Finds the length of the bytes representation of the base64 string
    size_t bytesLen = (base64Len * 3 / 4) - (base64String[base64Len - 1] == '=') - (base64String[base64Len - 2] == '=');
    uint8_t cipherBytes[bytesLen];

    // Converts the base64 to bytes
    if (base64ToBinary(base64String, cipherBytes, bytesLen) != 0) {
        printf("Error: Base64 to Binary\n");
        return 1;
    }

    uint8_t paddedPlaintext[bytesLen];
    const uint8_t key[] = "YELLOW SUBMARINE";
    uint8_t initVec[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    size_t paddedTextLen = 0;
#define BLOCK_SIZE 16
    // Decrypt the ciphertext
    if (CbcDecrypt(cipherBytes, bytesLen, key, initVec, paddedPlaintext, &paddedTextLen) != 0) {
        printf("Error: CBC Decrypt\n");
        return 1;
    }

    // Checks the length of the padded plaintext
    if (paddedTextLen <= BLOCK_SIZE || paddedTextLen >= SIZE_MAX - BLOCK_SIZE) {
        printf("Error: Padded text length is invalid\n");
        return 1;
    }
    size_t pad = paddedPlaintext[paddedTextLen - 1];
    if (pad > BLOCK_SIZE) {
        printf("Error: Padding value invalid\n");
        return 1;
    }

    uint8_t unpaddedOutput[paddedTextLen - pad];

    // Removes padding
    if (removePkcsPadding(paddedPlaintext, paddedTextLen, pad, unpaddedOutput) != 0) {
        printf("Error: Remove PKCS Padding\n");
        return 1;
    }

    printBytes(unpaddedOutput, paddedTextLen - pad);

    // printf("Now encrypt it, then decrypt again\n\n");

    // uint8_t padded[paddedTextLen];
    // uint8_t cipher[paddedTextLen];
    // size_t len;
    // uint8_t newPadded[paddedTextLen];
    // PkcsPadding(unpaddedOutput, paddedTextLen - pad, 16, 4, padded);

    // CbcEncrypt(padded, paddedTextLen, (unsigned char*)key, initVec, cipher, &len);

    // printBytes(cipher, paddedTextLen);
    // printf("\nDecryption:\n\n");

    // CbcDecrypt(cipher, paddedTextLen, (unsigned char*)key, initVec, newPadded, &len);
    // printBytes(newPadded, paddedTextLen - 4);

    return 0;
}
