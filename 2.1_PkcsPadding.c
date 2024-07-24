#include "aes_ciphers.h"
#include "core_functions.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char input[] = "YELLOW SUBMARINE";
    size_t inputLen = strlen(input);

    int blockLen = 20;
    size_t pad = blockLen - (inputLen % blockLen); // How much do we need to pad

    if (inputLen == 0 || inputLen >= SIZE_MAX - pad) {
        printf("Error: Input length is invalid\n");
        return 1;
    }
    uint8_t padOutput[inputLen + pad];

    // Applies the padding
    if (PkcsPadding((uint8_t*)input, inputLen, blockLen, pad, padOutput) != 0) {
        printf("Error: PKCS Padding\n");
        return 1;
    }

    // Printing the output to check correctness
    if (printBytes(padOutput, inputLen) != 0) {
        printf("Error: Print Bytes\n");
        return 1;
    }

    for (size_t j = inputLen; j < inputLen + pad; j++) {
        printf("%02x", padOutput[j]);
    }
    printf("\n");

    return 0;
}
