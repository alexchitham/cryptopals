#include "core_functions.h"

#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int printBytes(const uint8_t* bytes, size_t byteLen)
{
    // Argument checks
    if (bytes == NULL) {
        return 1;
    }

    if (byteLen == 0 || byteLen >= SIZE_MAX - 1) {
        printf("Error: Bytes length is invalid\n");
        return 1;
    }

    // Creates a new string and converts each bytes into it's ASCII character
    char stringOutput[byteLen + 1];
    for (size_t i = 0; i < byteLen; i++) {
        stringOutput[i] = (char)bytes[i];
    }
    stringOutput[byteLen] = '\0';

    // Print result
    printf("%s\n", stringOutput);
    return 0;
}

/**
 * Converts a Hex character into it's denary equivalent.
 *
 * @param hexDigit Hex character that will be converted
 *
 * @returns The denary value of the hex character on success, -1 if the hex character is invalid.
 */
static int HexCharToInt(const char hexDigit)
{
    int ascHex = (uint8_t)hexDigit;
    if (ascHex >= '0' && ascHex <= '9') {
        return (ascHex - '0');
    }
    if (ascHex >= 'a' && ascHex <= 'z') {
        return (ascHex - 'a' + 10);
    }
    if (ascHex >= 'A' && ascHex <= 'Z') {
        return (ascHex - 'A' + 10); // Accounts for upper and lower case hex
    }

    return -1;
}

int HexToBytes(const char* hexString, size_t byteLen, uint8_t* bytes)
{
    // Argument checks
    if (hexString == NULL || bytes == NULL) {
        return -1;
    }

    size_t hexLen = strlen(hexString);
    if (hexLen == 0 || hexLen >= SIZE_MAX - 1) {
        printf("Error: Hex length is invalid\n");
        return 1;
    }
    if (byteLen != (hexLen + 1) / 2) {
        return -2;
    }

    size_t curIndex = 0;

    // Moving through hex string two at a time, as 2 hex = 1 byte
    for (size_t i = 0; i < hexLen; i += 2) {
        // Variables for two hex characters, as they will form 1 byte
        char leftHex = hexString[i];
        char rightHex = '0';
        if (i < hexLen - 1) {
            rightHex = hexString[i + 1]; // If hex string is odd in length (working left to right) ...
        }
        else {
            rightHex = '0'; // ... Fill with 0
        }

        // Check for invalid characters
        if (HexCharToInt(rightHex) == -1 || HexCharToInt(leftHex) == -1) {
            printf("Error: Hex Char to Int, not a hex digit\n");
            return -3;
        }

        // Construct each byte using two hex characters
        int byte = HexCharToInt(rightHex) + (HexCharToInt(leftHex) * 16);
        if (byte < 0 || byte > 255) {
            printf("Error: Byte value is invalid\n");
            return 1;
        }
        bytes[curIndex] = byte;

        if (curIndex > SIZE_MAX - 1) {
            printf("Error: Index overflow\n");
            return 1;
        }
        curIndex++;
    }
    return 0;
}

int binaryXOR(const uint8_t* binary1, const uint8_t* binary2, uint8_t* outputXor, size_t len)
{
    // Argument checks
    if (binary1 == NULL || binary2 == NULL || outputXor == NULL) {
        return -1;
    }
    if (len == 0 || len >= SIZE_MAX) {
        return 1;
    }

    // XOR on each byte in the array
    for (size_t i = 0; i < len; i++) {
        outputXor[i] = binary1[i] ^ binary2[i];
    }
    return 0;
}

/**
 * Converts an integer to its corresponding Hex character.
 *
 * @param num The integer to be converted into a hex character
 *
 * @returns The hex character conversion on success, a null terminator on failure
 */
static char IntToHexChar(int num)
{
    if (num >= 0 && num < 10) {
        return ((char)(num + '0'));
    }
    if (num >= 10 && num < 16) {
        return ((char)(num - 10 + 'a'));
    }
    printf("Error: Int to Hex Char\n");
    return '\0';
}

int BytesToHex(const uint8_t* bytes, size_t byteLen, char* hexOutput, size_t hexLen)
{
    // Argument checks
    if (bytes == NULL || hexOutput == NULL) {
        return 1;
    }
    if (byteLen == 0 || hexLen == 0 || hexLen > SIZE_MAX - 1 || byteLen != (hexLen + 1) / 2) {
        printf("Error: Byte length or hex length is invalid\n");
        return 1;
    }

    size_t curIndex = 0;

    // Goes through each byte at a time
    for (size_t i = 0; i < byteLen; i++) {

        // Impossible for IntToHexChar to fail, as bytes[i] is a uint_8 so must be 0-255, and 0-15 when divided by 16
        hexOutput[curIndex++] = IntToHexChar((bytes[i] / 16)); // Finds the first hex digit of the current byte
        if (curIndex != hexLen) {
            hexOutput[curIndex++] = IntToHexChar((bytes[i] - ((bytes[i] / 16) * 16))); // Finds the second hex digit if required
        }
    }
    hexOutput[hexLen] = '\0';
    return 0;
}

/**
 * Function that finds the probability of a given character
 *
 * @param asc Byte value we are treating as an ASCII representation to find its probability
 * @param probTable Pointer to the buffer containing all the letter probabilities
 *
 * @returns The probability of the letter from the table, or 0 for obscure characters
 */
static double getProb(const uint8_t asc, const double* probTable)
{
    const double multiplyer = 10.0;
    size_t letter = 0;

    // Lower case letters accounted for
    if (asc >= 97 && asc < 123) {
        letter = asc - 'a';
        return (multiplyer * probTable[letter]);
    }

    // Upper case letters accounted for
    if (asc >= 65 && asc < 91) {
        letter = asc - 'A';
        return (multiplyer * probTable[letter]);
    }

    // Space account for
    if (asc == ' ') {
        return 1.3;
    }

    // Otherwise return a probability of 0
    return 0.0;
}

int UpdateBestText(double* currentScore, double* bestScore, size_t bytesLen, const uint8_t currentText[bytesLen], uint8_t* bestText)
{
    // Argument checks
    if (currentScore == NULL || bestScore == NULL || currentText == NULL || bestText == NULL) {
        return 1;
    }
    if (bytesLen == 0 || bytesLen >= SIZE_MAX) {
        return 1;
    }

    const double probTable[] = {
        0.082, 0.015, 0.028, 0.043,   0.127, 0.022, 0.02,  0.061, 0.07,   0.0015, 0.0077, 0.04, 0.024,
        0.067, 0.075, 0.019, 0.00095, 0.06,  0.063, 0.091, 0.028, 0.0098, 0.024,  0.0015, 0.02, 0.00074}; // Letter frequency probabilities

    // Find the score of the current text
    for (size_t k = 0; k < bytesLen; k++) {
        uint8_t letter = currentText[k];
        *currentScore += getProb(letter, probTable);
    }

    // Replace the best text if needed
    if (*currentScore > *bestScore) {
        *bestScore = *currentScore;
        for (size_t i = 0; i < bytesLen; i++) {
            bestText[i] = currentText[i];
        }
    }
    return 0;
}

int MostProbableXorText(const uint8_t* cipher, uint8_t* plaintext, size_t bytesLen)
{
    // Argument checks
    if (cipher == NULL || plaintext == NULL) {
        return 1;
    }
    if (bytesLen == 0 || bytesLen > SIZE_MAX) {
        return 1;
    }

    uint8_t bestText[bytesLen]; // Will always point to the best text we have found so far
    memset(bestText, 0, bytesLen);
    double bestScore = 0;          // Initiate the best score
    uint8_t currentText[bytesLen]; // Will point to the plaintext we are currently looking at
    memset(currentText, 0, bytesLen);
    double currentScore = 0;

    // Try each possible byte value as the key
    for (size_t i = 0; i <= UINT8_MAX; i++) {
        currentScore = 0; // Reset score
        uint8_t key[bytesLen];

        // Makes key same length as cipher
        for (size_t j = 0; j < bytesLen; j++) {
            key[j] = i;
        }

        // Decrypts the cipher
        if (binaryXOR(cipher, key, currentText, bytesLen) != 0) {
            printf("Error: Binary XOR\n");
            return -1;
        }

        // Updates the best text if the current one has a better score
        if (UpdateBestText(&currentScore, &bestScore, bytesLen, currentText, bestText) != 0) {
            printf("Error: Update best text\n");
            return -1;
        }
    }

    // Copy in the most likely text
    memcpy(plaintext, bestText, bytesLen);
    return 0;
}

int SingleByteXorCipher(const char* cipherHex, size_t hexLen, uint8_t* plaintext, size_t bytesLen)
{
    // Argument checks
    if (cipherHex == NULL || plaintext == NULL) {
        return 1;
    }
    if (bytesLen == 0 || bytesLen >= SIZE_MAX - 1 || hexLen == 0 || hexLen >= SIZE_MAX - 1) {
        printf("Error: Input lengths is invalid\n");
        return 1;
    }
    if (bytesLen != (hexLen + 1) / 2) {
        return 1;
    }

    // Buffer to store the cipher in bytes
    uint8_t binaryCipher[bytesLen];
    memset(binaryCipher, 0, bytesLen);

    // Converts cipher from hex to binary
    if (HexToBytes(cipherHex, bytesLen, binaryCipher) != 0) {
        printf("Error: Hex to bytes\n");
        return -1;
    }

    // Calls the function that tests all single byte keys to find the most probable plaintext
    if (MostProbableXorText(binaryCipher, plaintext, bytesLen) != 0) {
        printf("Error: Most Probable XOR text\n");
        return -1;
    }
    return 0;
}

/**
 * Given a string and letter, finds the index in the string where that letter occurs
 *
 * @param txt Pointer to the buffer storing the string
 * @param letter Letter that is being searched for
 *
 * @returns The index of the letter on success, -1 if the letter is not found
 */
static int findIndex(const char* txt, char letter)
{
    int index = 0;
    if (strlen(txt) >= INT_MAX) {
        printf("Error: String too long\n");
        return 1;
    }
    while (txt[index] != letter) {
        if (index == (int)strlen(txt) - 1) {
            return -1;
        }
        index++;
    }
    return index;
}

int base64ToBinary(const char* base64, uint8_t* bytes, size_t bytesLen)
{
    // Argument checks
    if (base64 == NULL || bytes == NULL || bytesLen <= 0) {
        return -1;
    }

    size_t base64Len = strlen(base64);
    if (bytesLen != (base64Len * 3 / 4) - (base64[base64Len - 1] == '=') - (base64[base64Len - 2] == '=')) {
        return -2;
    }

    const char base64Lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t byteindex = 0;

    // Base64 are always in groups of 4 characters, each one translate to 3 bytes
    for (size_t i = 0; i < base64Len; i += 4) {
        uint32_t chunk = 0;

        // Build up the chunk with 4 base64 characters
        for (int j = 0; j < 4; j++) {

            if (base64[i + j] != '=') {

                // Check for invalid base64 character
                if (findIndex(base64Lookup, base64[i + j]) == -1) {
                    printf("Letter is at index %lu\n", i + j);
                    printf("Error: Find index\n");
                    return -3;
                }

                // Bit shift and add to the chunk
                int val = findIndex(base64Lookup, base64[i + j]) << (18 - (6 * j));
                if (val < 0 || val >= INT32_MAX) {
                    printf("Base64 value is invalid\n");
                    return 1;
                }
                chunk |= (findIndex(base64Lookup, base64[i + j]) << (18 - (6 * j)));
            }
        }

        // Translate that base64 chunk into 3 bytes
        for (int k = 0; k < 3; k++) {
            if (byteindex < bytesLen) {
                bytes[byteindex++] = (chunk >> (16 - (k * 8))) & 0xFF;
            }
        }
    }
    return 0;
}

int fileLineLength(const char* fileName, size_t* len)
{
    // Argument checks
    if (fileName == NULL || len == NULL) {
        return 1;
    }

    FILE* fptr;
    fptr = fopen(fileName, "r");
    int ret = 0;

    char* buff = NULL;

    // File opening error
    if (fptr == NULL) {
        printf("Error: File pointer was null\n");
        return -1;
    }

    // Reads the first line of the file
    if (getline(&buff, len, fptr) != -1) {
        *len = strlen(buff) - 1; // Saves its length, removes 1 as it counts new line
    }
    else {
        printf("Error: Get Line function\n");
        ret = -1;
    }

    // Close the file
    if (fclose(fptr) != 0) {
        printf("Error: fclose\n");
        return 1;
    }
    return ret;
}

int findFileLength(const char* fileName, size_t* len)
{
    // Argument checks
    if (fileName == NULL || len == NULL) {
        return 1;
    }

    // Open the file
    FILE* fptr;
    fptr = fopen(fileName, "r");
    if (fptr == NULL) {
        printf("Error: File pointer was null\n");
        return -1;
    }

    // Relevant variables
    char* buff = NULL;
    size_t lineLen = 0;
    size_t totalLen = 0;

    // Reads every line of the file and counts the characters it reads
    while (getline(&buff, &lineLen, fptr) != -1) {
        totalLen += strlen(buff);
        if (buff[strlen(buff) - 1] == '\n' && totalLen > 0) {
            totalLen -= 1;
        }
    }

    *len = totalLen;

    // Close the file
    if (fclose(fptr) != 0) {
        printf("Error: fclose\n");
        return 1;
    }
    return 0;
}

int readLongFile(const char* fileName, char* fileString, size_t strLen)
{
    // Argument checks
    if (fileName == NULL || fileString == NULL) {
        return 1;
    }

    // Open the file
    FILE* fptr;
    fptr = fopen(fileName, "r");
    if (fptr == NULL) {
        printf("Error: File pointer was null\n");
        return -1;
    }

    // Relevant variables
    char* buff = NULL;
    size_t lineLen = 0;
    size_t index = 0;

    // Reads each line
    while (getline(&buff, &lineLen, fptr) != -1) {

        // For each character, check its value and copy it into predefined buffer
        for (size_t i = 0; i < strlen(buff); i++) {
            if (buff[i] != '\n' && buff[i] != '\0') {
                fileString[index] = buff[i];

                // Size checks
                if (index < SIZE_MAX) {
                    index++;
                }
            }
        }
    }
    fileString[strLen] = '\0';

    // Close file
    if (fclose(fptr) != 0) {
        printf("Error: fclose\n");
        return 1;
    }
    return 0;
}
