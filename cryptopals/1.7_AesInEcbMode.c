#include "aes_ciphers.h"
#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int AesInEcb(const char* base64Cipher, const uint8_t* key, uint8_t* output, size_t bytesLen, size_t* decryptLen);

int main()
{

    size_t base64Len;

    // Find the length of the cipher in the file
    if (findFileLength("1.7_Cipher.txt", &base64Len) != 0) {
        printf("Error: Find file length\n");
        return 1;
    }

    if (base64Len <= 0 || base64Len >= SIZE_MAX - 1) {
        printf("Error: Base64 length is invalid\n");
        return 1;
    }
    char inputString[base64Len + 1]; // Create an array of the correct length

    // Read the cipher into our prepared array
    if (readLongFile("1.7_Cipher.txt", inputString, base64Len) != 0) {
        printf("Error: Read long string\n");
        return 1;
    }

    size_t bytesLen = (base64Len * 3 / 4) - (inputString[base64Len - 1] == '=') - (inputString[base64Len - 2] == '=');
    if (bytesLen == 0 || bytesLen >= SIZE_MAX) {
        return 1;
    }

    uint8_t result[bytesLen];
    size_t decryptLen = 0;
    const uint8_t key[] = "YELLOW SUBMARINE";

    if (AesInEcb(inputString, key, result, bytesLen, &decryptLen) != 0) {
        printf("Error: AES in ECB\n");
        return 1;
    }

    printBytes(result, decryptLen);
    return 0;
}

int AesInEcb(const char* base64Cipher, const uint8_t* key, uint8_t* output, size_t bytesLen, size_t* decryptLen)
{

    if (base64Cipher == NULL || key == NULL || output == NULL || decryptLen == NULL) {
        return -1;
    }

    if (bytesLen == 0 || bytesLen >= SIZE_MAX) {
        return 1;
    }

    uint8_t cipher[bytesLen]; // Create an array for cipher after converting from base64

    if (base64ToBinary(base64Cipher, cipher, bytesLen) != 0) {
        printf("Error: Base64 to Binary\n");
        return 1;
    }

    // Perform the decryption on the bytes
    if (decryptECB(cipher, bytesLen, key, output, decryptLen) != 0) {
        printf("Error: Decrypt ECB\n");
        return 1;
    }
    return 0;
}
