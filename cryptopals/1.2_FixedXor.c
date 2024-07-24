#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char IntToHexChar(int num);
int FixedXOR(const char* hex1, const char* hex2, char* hexOutput, size_t hexLen);

int main()
{

    // The two test inputs
    const char hex1[] = "1234567890ABCDEF";
    const char hex2[] = "FEDCBA0987654321";
    size_t hexLen = strlen(hex1);

    // Length checks before defining variable array
    if (hexLen >= SIZE_MAX - 2) {
        printf("Error: Hex Length too long\n");
        return 1;
    }
    // Buffer for the final answer
    char result[hexLen + 1];

    // Performs the XOR
    if (FixedXOR(hex1, hex2, result, hexLen) != 0) {
        return 1;
    }

    // Check result
    printf("%s\n", result);
    return 0;
}

int FixedXOR(const char* hex1, const char* hex2, char* hexOutput, size_t hexLen)
{

    // Argument checks for validity
    if (hex1 == NULL || hex2 == NULL || hexOutput == NULL) {
        return 1;
    }
    if (strlen(hex1) != strlen(hex2) || hexLen != strlen(hex1)) {
        return 1;
    }

    if (hexLen <= 1 || hexLen >= SIZE_MAX - 1) {
        printf("Error: Hex length is invalid\n");
        return 1;
    }

    size_t byteLen = (hexLen + 1) / 2; // The length of the byte array

    // Define all the buffers
    uint8_t bytes1[byteLen];
    uint8_t bytes2[byteLen];
    uint8_t outputXor[byteLen];

    // Changes to bytes
    if (HexToBytes(hex1, byteLen, bytes1) != 0) {
        printf("Error: Hex to bytes\n");
        return 1;
    }
    if (HexToBytes(hex2, byteLen, bytes2) != 0) {
        printf("Error: Hex to Bytes\n");
        return 1;
    }

    // XOR the two byte arrays
    if (binaryXOR(bytes1, bytes2, outputXor, byteLen) != 0) {
        printf("Error: Binary XOR\n");
        return 1;
    }

    // Converts back to hex
    if (BytesToHex(outputXor, byteLen, hexOutput, hexLen) != 0) {
        printf("Error: Bytes to Hex\n");
        return 1;
    }

    return 0;
}
