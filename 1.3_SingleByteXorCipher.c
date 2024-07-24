#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{

    // Defines the test input
    char test[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    size_t hexLen = strlen(test);

    // Length checks
    if (hexLen <= 1 || hexLen >= SIZE_MAX - 2) {
        printf("Error: Hex Length is invalid\n");
        return 1;
    }

    // Predefined buffer for the results
    size_t resultLen = (hexLen + 1) / 2;
    uint8_t result[resultLen];

    // Break the single byte XOR encryption
    if (SingleByteXorCipher(test, hexLen, result, resultLen) != 0) {
        return 1;
    }

    // Print the result
    if (printBytes(result, resultLen) != 0) {
        return 1;
    }

    return 0;
}