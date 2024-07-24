#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int DetectSingleCharXor(const char* fileName, uint8_t* plaintext, size_t bytesLen);

int main()
{

    // Predefined buffer for the result
    size_t resultLen = (60 + 1) / 2;
    uint8_t result[resultLen];

    // Detect the single char XOR
    if (DetectSingleCharXor("1.4_Ciphers.txt", result, resultLen) != 0) {
        return 1;
    }

    // Print result
    if (printBytes(result, resultLen) != 0) {
        printf("Error: Print bytes\n");
        return 1;
    }
    return 0;
}

int DetectSingleCharXor(const char* fileName, uint8_t* plaintext, size_t bytesLen)
{
    if (fileName == NULL || plaintext == NULL) {
        return 1;
    }

    // Length check on arguments
    if (bytesLen == 0 || bytesLen >= SIZE_MAX) {
        printf("Error: Byte length is invalid\n");
        return 1;
    }

    FILE* fptr;
    fptr = fopen(fileName, "r");

    // File checks
    if (fptr == NULL) {
        printf("Error: File pointer was null\n");
        return 1;
    }

    // All relevant variables
    int ret = 0;
    char* cipherBuff = NULL;
    size_t lineLen = 0;
    char cipher[60 + 1];
    uint8_t bestText[bytesLen];
    memset(bestText, 0, bytesLen);
    double bestScore = 0;
    uint8_t currentText[bytesLen];
    memset(currentText, 0, bytesLen);
    double currentScore;

    // Reads each line of the file until it gets to the end
    while (getline(&cipherBuff, &lineLen, fptr) != -1) {
        currentScore = 0;
        for (size_t i = 0; i < strlen(cipherBuff) - 1; i++) {
            cipher[i] = cipherBuff[i];
        }
        cipher[strlen(cipherBuff)] = '\0';

        if (SingleByteXorCipher(cipher, 60, currentText, bytesLen) != 0) // Finds the best decryption for each line
        {
            printf("Error: Single byte XOR cipher\n");
            ret = 1;
            goto close_file;
        }

        // Replaces our current best guess if needed
        if (UpdateBestText(&currentScore, &bestScore, bytesLen, currentText, bestText) != 0) {
            printf("Error: Update best text\n");
            ret = 1;
            goto close_file;
        }
    }

    memcpy(plaintext, bestText, bytesLen);

close_file:
    if (fclose(fptr) != 0) {
        printf("Error: fclose\n");
        return 1;
    }
    return ret;
}
