#ifndef CORE_FUNCTIONS_H
#define CORE_FUNCTIONS_H

#include <stddef.h>
#include <stdint.h>

/**
 * Print a byte array as it's human readable ASCII characters.
 *
 * @param bytes Pointer to the buffer that contains the bytes
 * @param byteLen Length of the bytes buffer
 *
 * @returns 0 on success, 1 if the bytes pointer is null
 */
int printBytes(const uint8_t* bytes, size_t byteLen);

/**
 * Converts a hex encoded string into bytes, and copies into a pre-defined buffer.
 *
 * @param hexString Pointer to the string containing the Hex value
 * @param byteLen Length of the predefined bytes buffer
 * @param bytes Pointer to the buffer that will contain the output bytes
 *
 * @returns 0 on success, -1 if one of the pointers is null, -2 if the byte length provided is incorrect,
 * -3 if the hex string contains an invalid character
 */
int HexToBytes(const char* hexString, size_t byteLen, uint8_t* bytes);

/**
 * Performs the binary XOR operation on two byte buffers and copies the output into a pre-defined buffer.
 *
 * @param binary1 Pointer to the first buffer of bytes
 * @param binary2 Pointer to the second buffer of bytes
 * @param outputXor Pointer to the buffer that will contain the output bytes
 * @param len Length of all the byte buffers
 *
 * @returns 0 on success, 1 if the any of the pointers are null
 */
int binaryXOR(const uint8_t* binary1, const uint8_t* binary2, uint8_t* outputXor, size_t len);

/**
 * Converts a buffer of bytes into hex characters, and copies into a pre-defined string.
 *
 * @param bytes Pointer to the buffer that contains the bytes
 * @param byteLen Length of the bytes buffer
 * @param hexOutput Pointer to the string that will contain the hex output
 * @param hexLen The length of the pre-defined hex string (but length is really hexLen + 1) as it has room for \0
 *
 * @returns 0 on success, 1 if any of arguments are invalid
 */
int BytesToHex(const uint8_t* bytes, size_t byteLen, char* hexOutput, size_t hexLen);

/**
 * Compares a potential plaintext output to the best one found so far, and will replace it if the new text is more likely.
 * The score is calculated using letter frequency probabilities, so a higher score means the text is more likely
 * to be the correct plaintext we are searching for.
 *
 * @param currentScore Pointer to the current score variable where we will calculate the score of the plaintext
 * @param bestScore Pointer to the highest score of all the potential plaintext outputs
 * @param currentText Address of the pointer to the buffer that contains the plaintext we are checking next
 * @param bestText Pointer to the buffer containing the most probable plaintext we have found so far
 * @param bytesLen Length of all the byte buffers
 *
 * @returns 0 on success, 1 if any of the pointers are null
 */
int UpdateBestText(double* currentScore, double* bestScore, size_t bytesLen, const uint8_t currentText[bytesLen], uint8_t* bestText);

/**
 * Breaks the single-byte XOR cipher by testing all the one byte ASCII characters in turn to find the most likely
 * plaintext output.
 *
 * @param cipher Pointer to the buffer containing the cipher text
 * @param plaintext Pointer to the buffer that will contain the most likely plaintext we find
 * @param bytesLen Length of all the byte buffers
 *
 * @returns 0 on success, 1 if any of the pointers are null, -1 if a function called is unsuccessful
 */
int MostProbableXorText(const uint8_t* cipher, uint8_t* plaintext, size_t bytesLen);

/**
 * Breaks the single-byte XOR cipher, but first converts the from hex to binary, then calling the
 * MostProbableXorText function.
 *
 * @param cipherHex Pointer to the hex string containing the cipher text
 * @param hexLen Length of the hex encoded cipher text
 * @param plaintext Pointer to the buffer that will contain the most likely plaintext we find
 * @param bytesLen Length of all the byte buffers
 *
 * @returns 0 on success, 1 if any of the pointers are null, -1 if a function called is unsuccessful
 */
int SingleByteXorCipher(const char* cipherHex, size_t hexLen, uint8_t* plaintext, size_t bytesLen);

/**
 * Converts a base64 encoded string into bytes, and copies into a pre-defined buffer.
 *
 * @param base64 Pointer to the base64 encoded string
 * @param bytes Pointer to the buffer that will contain the output bytes
 * @param bytesLen Length of the predefined bytes buffer
 *
 * @returns 0 on success, -1 if one of the pointers is null, -2 if the byte length provided is incorrect,
 * -3 if a function called is unsuccessful
 */
int base64ToBinary(const char* base64, uint8_t* bytes, size_t bytesLen);

/**
 * Finds the length of the first line of a text file, which does NOT count the new line
 * character or null termination as part of the total.
 *
 * @param fileName Pointer to the string containing the name of the file
 * @param len Pointer to the variable where the line length will be stored
 *
 * @returns 0 on success, 1 if either of the pointers are null, -1 for file reading errors
 */
int fileLineLength(const char* fileName, size_t* len);

/**
 * Finds the length of an entire file, which does NOT count the new line
 * characters or null terminations as part of the total.
 *
 * @param fileName Pointer to the string containing the name of the file
 * @param len Pointer to the variable where the file length will be stored
 *
 * @returns 0 on success, 1 if either of the pointers are null, -1 for file reading errors
 */
int findFileLength(const char* fileName, size_t* len);

/**
 * Reads the entire length of a file into a single pre-defined string, removing
 * new line characters, and null terminates at the end.
 *
 * @param fileName Pointer to the string containing the name of the file
 * @param string Pointer to the pre-defined string that will contain the file contents
 * @param strLen Length of the pre-defined string
 *
 * @returns 0 on success, 1 if either of the pointers are null, -1 for file reading errors
 */
int readLongFile(const char* fileName, char* string, size_t strLen);

#endif