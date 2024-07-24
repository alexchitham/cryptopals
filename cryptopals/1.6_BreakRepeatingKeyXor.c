#include "core_functions.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hammingDistance(const uint8_t* text1, const uint8_t* text2, size_t len, int* dis);
int FindBestKeyLen(const uint8_t* ciphertext, int* bestKeyLengths, int numOfLens);
int DecryptRepeatingKeys(uint8_t* plaintext, size_t txtLen, const uint8_t* ciphertext, const int* topKeys, int numKeys);
int BreakRepeatingKeyXor(const char* base64, size_t base64Len, uint8_t* output, size_t bytesLen);

int main()
{

    // Finds the length of the entire file string
    size_t base64Len;
    if (findFileLength("1.6_Cipher.txt", &base64Len) != 0) {
        printf("Error: Find file length\n");
        return 1;
    }

    if (base64Len == 0 || base64Len >= SIZE_MAX - 1) {
        printf("Error: File length is invalid\n");
        return 1;
    }

    // Defines the array storing the file string
    char inputString[base64Len + 1];
    if (readLongFile("1.6_Cipher.txt", inputString, base64Len) != 0) {
        printf("Error: Read long string\n");
        return 1;
    }

    // Defines buffer for the output bytes
    size_t bytesLen = (base64Len * 3 / 4) - (inputString[base64Len - 1] == '=') - (inputString[base64Len - 2] == '=');
    if (bytesLen == 0 || bytesLen >= SIZE_MAX) {
        printf("Error: Bytes length is invalid\n");
        return 1;
    }
    uint8_t output[bytesLen];

    // Function to break the encryption
    if (BreakRepeatingKeyXor(inputString, base64Len, output, bytesLen) != 0) {
        return 1;
    }

    // Check the output
    printBytes(output, bytesLen);
    return 0;
}

int BreakRepeatingKeyXor(const char* base64, size_t base64Len, uint8_t* output, size_t bytesLen)
{

    // Argument checks
    if (base64 == NULL || output == NULL) {
        return 1;
    }

    if (base64Len < 4 || base64Len >= SIZE_MAX || base64Len % 4 != 0) {
        printf("Error: Base64 length is invalid\n");
        return 1;
    }

    if (bytesLen < 3 || bytesLen >= SIZE_MAX) {
        printf("Error: Byte length is invalid\n");
        return 1;
    }

    if (bytesLen != (base64Len * 3 / 4) - (base64[base64Len - 1] == '=') - (base64[base64Len - 2] == '=')) {
        printf("Error: Base64 length is invalid\n");
        return 1;
    }

    // Converts the base64 to binary
    uint8_t bytes[bytesLen];
    memset(bytes, 0, bytesLen);
    if (base64ToBinary(base64, bytes, bytesLen) != 0) {
        printf("Error: Base64 to Binary\n");
        return 1;
    }

    int numOfKeyLengths = 5; // The number of possible key lengths we will try
    int topKeyLens[numOfKeyLengths];

    // Finds the most likely key lengths
    if (FindBestKeyLen(bytes, topKeyLens, numOfKeyLengths) != 0) {
        printf("Error: Find Best Key Length\n");
        return 1;
    }

    // Decrypt the message with most likely key lengths and find the most probable
    if (DecryptRepeatingKeys(output, bytesLen, bytes, topKeyLens, numOfKeyLengths) != 0) {
        printf("Error: Decrypt Repeating Keys\n");
        return 1;
    }

    return 0;
}

int DecryptRepeatingKeys(uint8_t* plaintext, size_t txtLen, const uint8_t* ciphertext, const int* topKeys, int numKeys)
{

    // Argument checks
    if (plaintext == NULL || ciphertext == NULL || topKeys == NULL) {
        return 1;
    }
    if (txtLen == 0 || txtLen >= SIZE_MAX - 2) {
        return 1;
    }

    uint8_t bestText[txtLen]; // All relevant variables
    memset(bestText, 0, txtLen);
    double bestScore = 0;
    uint8_t currentText[txtLen];
    memset(currentText, 0, txtLen);
    double currentScore;

    // Iterates through the most likely key lengths
    for (int i = 0; i < numKeys; i++) {
        int keyLen = topKeys[i];
        currentScore = 0;

        // Creates blocks, one block for each character in the key
        for (size_t j = 0; j < (size_t)keyLen; j++) {
            size_t blockLen = (txtLen / keyLen) + (j < (txtLen % keyLen)); // The length of each block depends on text and key length

            // Length checking
            if (blockLen == 0 || blockLen >= SIZE_MAX) {
                printf("Error: Block size is invalid\n");
                return 1;
            }
            uint8_t block[blockLen];

            for (size_t k = 0; k < blockLen; k++) {
                block[k] = ciphertext[j + (k * keyLen)]; // Fills the block with relevant ciphertext characters
            }

            uint8_t plaintxtBlock[blockLen]; // Makes a block of the same length for the plaintext

            // Finds the most likely plaintext for this block
            if (MostProbableXorText(block, plaintxtBlock, blockLen) != 0) {
                printf("Error: Most probable XOR text\n");
                return 1;
            }

            // Puts each plaintext block character back in the correct place in current text
            for (size_t pt = 0; pt < blockLen; pt++) {
                currentText[j + (pt * keyLen)] = plaintxtBlock[pt];
            }
        }

        // Updates the best text if the keyLen we tried produces more probable plaintext
        if (UpdateBestText(&currentScore, &bestScore, txtLen, currentText, bestText) != 0) {
            printf("Error: Update best text\n");
            return 1;
        }
    }
    // Copy the best text into our output buffer
    memcpy(plaintext, bestText, txtLen);

    return 0;
}

int FindBestKeyLen(const uint8_t* ciphertext, int* bestKeyLengths, int numOfLens)
{

    // Argument checks
    if (ciphertext == NULL || bestKeyLengths == NULL) {
        return 1;
    }

    // We search between key lengths of 2 to 40
    size_t smallestKey = 2;
    size_t biggestKey = 40;
    double keyLengthsHams[biggestKey - smallestKey + 1]; // Array to store the ham distance for each key length

    // Loop through every length
    for (size_t keyLen = smallestKey; keyLen <= biggestKey; keyLen++) {

        // Assuming the message to decrypt is at least 160 characters long
        uint8_t chunk1[keyLen];
        uint8_t chunk2[keyLen];
        uint8_t chunk3[keyLen];
        uint8_t chunk4[keyLen];
        for (size_t i = 0; i < keyLen; i++) {
            chunk1[i] = ciphertext[i];
            chunk2[i] = ciphertext[keyLen + i];
            chunk3[i] = ciphertext[(2 * keyLen) + i];
            chunk4[i] = ciphertext[(3 * keyLen) + i];
        }

        int hDistance = 0;
        double totalHam = 0;

        if (hammingDistance(chunk1, chunk2, keyLen, &hDistance) != 0) {
            printf("Error: Hamming distance\n");
            return 1;
        }
        totalHam += hDistance;

        if (hammingDistance(chunk3, chunk4, keyLen, &hDistance) != 0) {
            printf("Error: Hamminresultg distance\n");
            return 1;
        }
        totalHam += hDistance;

        if (hammingDistance(chunk2, chunk3, keyLen, &hDistance) != 0) {
            printf("Error: Hamming distance\n");
            return 1;
        }
        totalHam += hDistance;

        if (keyLen < smallestKey || keyLen > INT16_MAX) {
            printf("Error: Key length is too large\n");
            return 1;
        }
        keyLengthsHams[keyLen - smallestKey] = (totalHam / ((double)keyLen)) / 3.0;
    }

    // This for loop performs a partial insertion sort to find the top n keys with lowest hamming distance
    for (int i = 0; i < numOfLens; i++) {
        double bestHam = -1;
        int bestKey = smallestKey; // Will be reallocated but assigned for safety
        for (size_t j = 0; j < (biggestKey - smallestKey + 1); j++) {
            int currentKey = j + 2;
            double currentHam = keyLengthsHams[j];
            if (((currentHam < bestHam) && (currentHam >= 0)) || bestHam < 0) {
                bestHam = currentHam;
                bestKey = currentKey;
            }
        }
        bestKeyLengths[i] = bestKey;
        keyLengthsHams[bestKey - smallestKey] = -1;
    }
    return 0;
}

int hammingDistance(const uint8_t* text1, const uint8_t* text2, size_t len, int* dis)
{
    if (text1 == NULL || text2 == NULL || len <= 0) {
        return 1;
    }

    if (len > SIZE_MAX) {
        return 1;
    }

    int hDis = 0;

    uint8_t xor [len];
    if (binaryXOR(text1, text2, xor, len) != 0) {
        printf("Error: Binary XOR\n");
        return 1;
    }

    for (size_t byte = 0; byte < len; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            if ((xor[byte] >> bit) & 0x1) {

                if (hDis >= INT_MAX - 1) {
                    printf("Error: Counter overflow\n");
                    return 1;
                }
                hDis++; // Counts the number of differing bits
            }
        }
    }

    if (hDis < 0 || hDis > INT16_MAX / 3) {
        printf("Error: Hamming distance invalid\n");
        return 1;
    }

    *dis = hDis;
    return 0;
}
