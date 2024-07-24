#include "core_functions.h"
#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int binaryToBase64(const uint8_t* byteArr, size_t len, char* base64, size_t base64Len);
int HexToBase64(const char* hexString, size_t hexLen, char* base64, size_t base64Len);

int main()
{

    // The example input and expected output
    const char hexTest[] = "112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00";
    const char answer[] = "ESIzRFVmd4iZqrvM3e7/ABEiM0RVZneImaq7zN3u/wA=";

    // Length checks
    size_t hexLen = strlen(hexTest);
    if (hexLen == 0 || hexLen > SIZE_MAX - 2) {
        printf("Error: Hex Length is invalid\n");
        return 1;
    }

    // The length of the byte array
    size_t byteLen = (hexLen + 1) / 2;

    // Finds length of base64, any remainder means another set of 4 base64 digits
    size_t base64Len = (((byteLen / 3) + ((byteLen % 3) > 0)) * 4);
    if (base64Len == 0 || base64Len >= SIZE_MAX - 1) {
        printf("Base64 length is invalid\n");
        return 1;
    }

    char base64[base64Len + 1];

    // Calls the function for the conversion
    if (HexToBase64(hexTest, hexLen, base64, base64Len) != 0) {
        return 1;
    }

    // Checks solution
    printf("%s\n", base64);
    printf("%d\n", strcmp(base64, answer));

    return 0;
}

int HexToBase64(const char* hexString, size_t hexLen, char* base64, size_t base64Len)
{

    // Length checks of the arguments
    if (hexLen <= 1 || hexLen > SIZE_MAX - 1) {
        printf("Error: Hex length is invalid\n");
        return 1;
    }

    if (base64Len == 0 || base64Len >= SIZE_MAX - 1) {
        printf("Base64 length is invalid\n");
        return 1;
    }

    size_t byteLen = (hexLen + 1) / 2; // The length of the byte array
    uint8_t bytes[byteLen];

    if (base64Len != (((byteLen / 3) + ((byteLen % 3) > 0)) * 4)) {
        return 1;
    }

    // The hex value is now an array of bytes
    if (HexToBytes(hexString, byteLen, bytes) != 0) {
        printf("Error: HexToBytes\n");
        return 1;
    }

    // Changes byte array to base64
    if (binaryToBase64(bytes, byteLen, base64, base64Len) != 0) {
        printf("Error: binaryToBase64\n");
        return 1;
    }

    return 0;
}

int binaryToBase64(const uint8_t* byteArr, size_t len, char* base64, size_t base64Len)
{

    if (byteArr == NULL || base64 == NULL) {
        return 1;
    }

    if (len == 0 || len >= INT_MAX - 1) {
        printf("Error: Length is invalid\n");
        return 1;
    }

    int rem = (int)len % 3; // Need to look at groups of 3 bytes and will pad if a remainder exists
    int groupsOf3 = (int)len / 3;
    char base64Lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t base64Index = 0;

    for (int i = 0; i < groupsOf3 + (rem > 0); i++) // Going through groups of 3 and remainder
    {
        size_t num = (size_t)3 * i;
        uint32_t chunkOf24 = 0;
        if (i == groupsOf3) // If we don't have a multiple of 3 bytes
        {
            chunkOf24 = ((uint32_t)byteArr[num]) << 16; // With a remainder of 1, only one byte to shift
            if (rem == 2) {
                chunkOf24 = chunkOf24 | (byteArr[num + 1] << 8); // With a remainder of 2, two bytes to shift
            }
        }
        else {
            int64_t val = ((uint32_t)byteArr[num] << 16) | ((uint32_t)byteArr[num + 1] << 8) | (byteArr[num + 2]);
            if (val < 0) {
                printf("Error: Byte value is negative\n");
                return 1;
            }
            chunkOf24 = val; // Concatenates 3 bytes together
        }

        if (base64Index > SIZE_MAX - 5) {
            printf("Error: Base64 Index too large\n");
            return 1;
        }
        // Uses a mask to cancel out (make 0) all digits except the ones we want using 0111111 (3F) with AND (&)
        base64[base64Index++] = base64Lookup[(chunkOf24 >> 18) & 0x3F]; // Extracts the first 6 digits out of the 24 length binary number
        base64[base64Index++] = base64Lookup[(chunkOf24 >> 12) & 0x3F]; // Extracts the second 6 digits out of the 24 length binary number
        base64[base64Index++] = base64Lookup[(chunkOf24 >> 6) & 0x3F];
        base64[base64Index++] = base64Lookup[chunkOf24 & 0x3F]; // Extracts the last 6 digits out of the 24 length binary number
    }

    if (rem > 0) {
        base64[base64Index - 1] = '='; // Adds the padding as base64 must be a multiple of 4 in length
    }
    if (rem == 1) {
        base64[base64Index - 2] = '=';
    }
    base64[base64Len] = '\0'; // Null character at end
    return 0;
}
