#include "aes_ciphers.h"
#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int DetectEcbMode(const char* fileName, size_t hexLen, size_t bytesLen);

int main()
{

    size_t hexLen = 0;

    // Find the length of each line
    if (fileLineLength("1.8_Ciphers.txt", &hexLen) != 0) {
        printf("Error: File line length\n");
        return 1;
    }

    size_t byteLen = (hexLen + 1) / 2;

    if (DetectEcbMode("1.8_Ciphers.txt", hexLen, byteLen) != 0) {
        return 1;
    }

    return 0;
}

int DetectEcbMode(const char* fileName, size_t hexLen, size_t bytesLen)
{
    if (fileName == NULL || hexLen >= SIZE_MAX - 2) {
        return 1;
    }

    if (bytesLen == 0 || bytesLen >= SIZE_MAX) {
        return 1;
    }

    if (bytesLen != (hexLen + 1) / 2) {
        return 1;
    }

    if (hexLen == 0 || hexLen >= SIZE_MAX - 1) {
        printf("Error: Byte length is invalid\n");
        return 1;
    }

    FILE* fptr;
    fptr = fopen(fileName, "r");
    if (fptr == NULL) {
        printf("Error: File pointer was null\n");
        return 1;
    }
    int ret = 0;

    char* cipherBuff = NULL; // Relevant variables
    char cipher[hexLen + 1];
    int found = 0;
    uint8_t bytes[bytesLen];
    int lineNum = 1;
    size_t lineLen = 0;

    while (found == 0 && getline(&cipherBuff, &lineLen, fptr) != -1) // Reads each line in the file
    {
        for (size_t i = 0; i < hexLen; i++) {
            cipher[i] = cipherBuff[i];
        }
        cipher[hexLen] = '\0'; // Puts the line in a fresh array

        // Converts to bytes
        if (HexToBytes(cipher, bytesLen, bytes) != 0) {
            printf("Error: Hex to bytes\n");
            ret = 1;
            goto close_file;
        }

        // Finds the line and blocks that are repeated
        if (DetectEcbInLine(bytes, bytesLen, &found) != 0) {
            printf("Error: Detect ECB in line\n");
            ret = 1;
            goto close_file;
        }

        // If we found them (if they exist) we print the findings
        if (found == 1) {
            printf("in line %d\n", lineNum);
            goto close_file;
        }

        lineNum++;
    }

    if (found == 0) {
        printf("ECB not detected\n");
        ret = 1;
        goto close_file;
    }

close_file:
    if (fclose(fptr) != 0) {
        printf("Error: fclose\n");
        return 1;
    }

    return ret;
}
