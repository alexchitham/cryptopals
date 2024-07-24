#ifndef AES_CIPHERS_H
#define AES_CIPHERS_H

#include <stddef.h>
#include <stdint.h>

/**
 * Adds PKCS#7 padding to the end of the plaintext so that it is a multiple of the block size.
 *
 * @param msg Pointer to the buffer storing the unpadded plaintext
 * @param msgLen Length of the plaintext buffer
 * @param blockLen Length of the blocks being used in the encryption
 * @param pad Number of bytes being added to the end of the plaintext for padding
 * @param output Pointer to the buffer where the padded plaintext will be stored, which has a length of (msgLen + pad)
 *
 * @returns 0 on success, 1 if any pointers are null, -1 if the pad argument is not correct
 */
int PkcsPadding(const uint8_t* msg, size_t msgLen, size_t blockLen, size_t pad, uint8_t* output);

/**
 * Removes PKCS#7 padding from the end of the plaintext after it has been decrypted.
 *
 * @param padInput Pointer to the buffer storing the padded plaintext
 * @param paddedLength Length of the padded plaintext
 * @param pad Number of characters to be removed as padding
 * @param output Pointer to the buffer that will stored the unpadded plaintext, which has a length of (paddedLength - pad)
 */
int removePkcsPadding(const uint8_t* padInput, size_t paddedLength, size_t pad, uint8_t* output);

/**
 * Encrypts plaintext using the AES-128 cipher in ECB mode.
 *
 * @param plaintext Pointer to the buffer containing the plaintext
 * @param plaintextLen Length of the plaintext buffer
 * @param key Pointer to the buffer containing the key
 * @param ciphertext Pointer to the buffer that will contain the encrypted ciphertext
 * @param cipherLen Pointer to a variable where the length of the ciphertext will be stored
 *
 * @returns 0 on success, 1 if any of the pointers are null, -1 if a function called is unsuccessful
 */
int encryptECB(const uint8_t* plaintext, size_t plaintextLen, const uint8_t* key, uint8_t* ciphertext, size_t* cipherLen);

/**
 * Decrypts ciphertext using the AES-128 cipher in ECB mode.
 *
 * @param cipherText Pointer to the buffer containing the cipher text
 * @param cipherLen Length of the ciphertext buffer
 * @param key Pointer to the buffer containing the key
 * @param plaintext Pointer to the buffer that will contain the decrypted plaintext
 * @param plaintextLen Pointer to a variable where the length of the plaintext will be stored
 *
 * @returns 0 on success, 1 if any of the pointers are null, -1 if a function called is unsuccessful
 */
int decryptECB(const uint8_t* ciphertext, size_t cipherLen, const uint8_t* key, uint8_t* plaintext, size_t* plaintextLen);

/**
 * Encrypts plaintext using the AES-128 cipher in CBC mode.
 *
 * @param plaintext Pointer to the buffer containing the plaintext
 * @param plaintextLen Length of the plaintext buffer
 * @param key Pointer to the buffer containing the key
 * @param iv Pointer to the buffer containing the Initialisation Vector
 * @param ciphertext Pointer to the buffer that will contain the encrypted ciphertext
 * @param cipherLen Pointer to a variable where the length of the ciphertext will be stored
 *
 * @returns 0 on success, 1 if any of the pointers are null, -1 if a function called is unsuccessful
 */
int CbcEncrypt(const uint8_t* plaintext, size_t plaintextLen, const uint8_t* key, const uint8_t* initVec, uint8_t* ciphertext, size_t* cipherLen);

/**
 * Decrypts ciphertext using the AES-128 cipher in CBC mode.
 *
 * @param cipherText Pointer to the buffer containing the cipher text
 * @param cipherLen Length of the ciphertext buffer
 * @param key Pointer to the buffer containing the key
 * @param iv Pointer to the buffer containing the Initialisation Vector
 * @param plaintext Pointer to the buffer that will contain the decrypted plaintext
 * @param plaintextLen Pointer to a variable where the length of the plaintext will be stored
 *
 * @returns 0 on success, 1 if any of the pointers are null, -1 if a function called is unsuccessful
 */
int CbcDecrypt(const uint8_t* ciphertext, size_t cipherLen, const uint8_t* key, const uint8_t* initVec, uint8_t* plaintext, size_t* plaintextLen);

/**
 * Checks if any blocks in a ciphertext are identical to one another, as this suggests ECB was used for encryption.
 *
 * @param cipher Pointer to the buffer containing the cipher text
 * @param byteLen Length of the ciphertext buffer
 * @param verdict Integer variable that is set to 1 if ECB is detected or 0 if not
 *
 * @returns 0 on success, 1 if any arguments are invalid
 */
int DetectEcbInLine(const uint8_t* cipher, size_t byteLen, int* verdict);

/**
 * Produces random numbers in a buffer of bytes.
 *
 * @param text Pointer to the buffer of bytes that will store the random numbers
 * @param textSize Length of the buffer of bytes
 *
 * @returns 0 on success, 1 if any arguments are invalid, -1 if RNG fails
 */
int RandomAesText(uint8_t* text, size_t textSize);

/**
 *
 */

#endif
