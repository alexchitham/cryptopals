#include "aes_ciphers.h"
#include "core_functions.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 16

struct kv {
    char* key;
    char* value;
};

int parser(const char* inputString, struct kv* object);
int create_key_value(struct kv* object);
int free_key_value(struct kv* object);
int print_key_value(const struct kv* object);
int profile_for(const char* email, char** encoding);
int encryptProfile(char* profile, const uint8_t* key, uint8_t** ciphertext, size_t* cipherLen);
int decryptProfile(const uint8_t* ciphertext, size_t cipherLen, struct kv* object, const uint8_t* key);

int main()
{

    int blockLen = 16;
    uint8_t key[blockLen];

    // Generate a random key
    if (RandomAesText(key, blockLen) != 0) {
        printf("Error: Random Aes Text for the key\n");
        return -1;
    }

    // Create an array of 3 key-value structs, and pre-fill it with NULL
    struct kv object[3];
    if (create_key_value(object) != 0) {
        printf("Error: Create key-value\n");
        return 1;
    }

    // Want this profile: email:admin@foo.  com&uid=10&role=  admin 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b  **(the encrypted version)**

    // Input 1: "admin@foo.com"
    // Produces: email:admin@foo.  com&uid=10&role=  user  **(will be padded when encrypted)**
    // From ciphertext:
    // Can use the first 2 blocks in our ciphertext, and just replace the "user" at the end

    // Input 2: "fo@bar.comadmin 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b"  **(The padding is needed as that contributes to the encrypted block)**
    // Produces: email:fo@bar.com  admin 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b  &uid=10&role=use  r
    // From ciphertext:
    // Take the second block and use it as the third block in our ciphertext

    // Create a profile for the first input
    char* encoding = NULL;
    if (profile_for("admin@foo.com", &encoding) != 0) {
        printf("Error: profile_for\n");
        return 1;
    }

    // Encrypt the first profile
    uint8_t* cipher = NULL;
    size_t cipherLen = 0;
    if (encryptProfile(encoding, key, &cipher, &cipherLen) != 0) {
        printf("Error: Encrypt Profile\n");
        return 1;
    }

    // Create the template for our admin profile encryption and copy the parts we need from input 1
    size_t adminSize = 16 + 16 + 16;
    uint8_t adminProfile[adminSize];
    memcpy(adminProfile, cipher, 32);
    free(cipher);
    cipher = NULL;

    // Create the second input string
    char input2[10 + 16 + 1];
    memcpy(input2, "fo@bar.comadmin", 15);
    for (size_t i = 15; i < 16 + 10; i++) {
        input2[i] = (char)11;
    }
    input2[10 + 16] = '\0';

    // Create the second profile
    if (profile_for(input2, &encoding) != 0) {
        printf("Error: profile_for\n");
        return 1;
    }

    // Encrypt the second profile
    if (encryptProfile(encoding, key, &cipher, &cipherLen) != 0) {
        printf("Error: Encrypt Profile\n");
        return 1;
    }

    // Copy in the parts we need from the second input
    memcpy(adminProfile + 32, cipher + 16, 16);
    free(cipher);

    // Decrypt our ciphertext and show it creates an admin profile
    decryptProfile(adminProfile, adminSize, object, key);

    print_key_value(object);
    free_key_value(object);

    return 0;
}

int profile_for(const char* email, char** encoding)
{
    if (email == NULL || encoding == NULL) {
        return 1;
    }

    // Check for invalid inputs
    for (size_t i = 0; i < strlen(email); i++) {
        if (email[i] == '&' || email[i] == '=') {
            printf("Error: Invalid email, no & or = permitted.\n");
            return 1;
        }
    }

    // Creates the encoding string with the user email and other fixed information
    const char otherInfo[] = "&uid=10&role=user";
    const char emailString[] = "email=";

    if (strlen(otherInfo) >= SIZE_MAX - strlen(emailString) || strlen(email) >= SIZE_MAX - strlen(otherInfo) - strlen(emailString)) {
        printf("Error: Profile encoding length is too long\n");
    }

    size_t encodingLen = strlen(emailString) + strlen(email) + strlen(otherInfo);

    char* encodingString = (char*)malloc((encodingLen + 1) * sizeof(char));
    if (encodingString == NULL) {
        printf("Error: Could not allocate memory\n");
        return 1;
    }
    memcpy(encodingString, emailString, strlen(emailString));
    memcpy(encodingString + strlen(emailString), email, strlen(email));
    memcpy(encodingString + strlen(emailString) + strlen(email), otherInfo, strlen(otherInfo));
    encodingString[encodingLen] = '\0';

    *encoding = encodingString;

    return 0;
}

int encryptProfile(char* profile, const uint8_t* key, uint8_t** ciphertext, size_t* cipherLen)
{
    if (profile == NULL || key == NULL || ciphertext == NULL || cipherLen == NULL) {
        return 1;
    }

    int ret = 0;

    // Defining the plaintext
    size_t blockLen = BLOCK_SIZE;
    size_t plaintextLen = strlen(profile);
    uint8_t* plaintext = (uint8_t*)profile;

    if (plaintextLen == 0 || plaintextLen >= SIZE_MAX - blockLen) {
        printf("Profile length is invalid\n");
        return 1;
    }

    size_t pad = blockLen - (plaintextLen % blockLen); // How much do we need to pad
    size_t paddedLen = plaintextLen + pad;
    uint8_t paddedPlaintext[paddedLen];
    memset(paddedPlaintext, 0, paddedLen);

    uint8_t* cipher = (uint8_t*)malloc(paddedLen);
    if (cipher == NULL) {
        printf("Error: Could not allocate memory\n");
        ret = 1;
        goto free_profile;
    }

    *ciphertext = cipher;

    // Applies the padding
    if (PkcsPadding(plaintext, plaintextLen, blockLen, pad, paddedPlaintext) != 0) {
        printf("Error: PKCS Padding\n");
        ret = 1;
        free(cipher);
        goto free_profile;
    }

    // Encrypts the profile with padding
    if (encryptECB(paddedPlaintext, paddedLen, key, cipher, cipherLen) != 0) {
        printf("Error: Encrypt ECB\n");
        ret = 1;
        free(cipher);
        goto free_profile;
    }

// Error handling of the memory allocation
free_profile:
    free(profile);

    return ret;
}

int decryptProfile(const uint8_t* ciphertext, size_t cipherLen, struct kv* object, const uint8_t* key)
{
    if (ciphertext == NULL || object == NULL || key == NULL) {
        return 1;
    }

    // Length checks
    if (cipherLen == 0 || cipherLen > SIZE_MAX) {
        printf("Error: Ciphertext length is invalid\n");
        return 1;
    }

    uint8_t paddedPlaintext[cipherLen];
    memset(paddedPlaintext, 0, cipherLen);
    size_t paddedTextLen = 0;

    // Decrypt the ciphertext
    if (decryptECB(ciphertext, cipherLen, key, paddedPlaintext, &paddedTextLen) != 0) {
        printf("Error: Decrypt ECB\n");
        return 1;
    }

    // Length checks
    if (paddedTextLen <= BLOCK_SIZE || paddedTextLen >= SIZE_MAX - 1 - BLOCK_SIZE) {
        printf("Padded text length is invalid\n");
        return 1;
    }

    size_t pad = paddedPlaintext[paddedTextLen - 1];
    if (pad > BLOCK_SIZE) {
        printf("Error: Padding value invalid\n");
        return 1;
    }
    uint8_t unpaddedOutput[paddedTextLen - pad];
    memset(unpaddedOutput, 0, paddedTextLen - pad);

    // Remove the padding on the plaintext
    if (removePkcsPadding(paddedPlaintext, paddedTextLen, pad, unpaddedOutput) != 0) {
        printf("Error: Remove PKCS Padding\n");
        return 1;
    }

    // Convert the bytes to a string for parsing
    char profile[paddedTextLen - pad + 1];
    memcpy(profile, unpaddedOutput, paddedTextLen - pad);
    profile[paddedTextLen - pad] = '\0';

    // Parse the profile string, and put into an array of structs
    if (parser(profile, object) != 0) {
        printf("Error: Parser\n");
        return 1;
    }

    return 0;
}

int parser(const char* inputString, struct kv* object)
{

    if (inputString == NULL || object == NULL) {
        return 1;
    }

    // Necessary variables
    size_t inputLen = strlen(inputString);
    size_t start = 0;
    size_t currentKv = 0;
    char prevSymbol = '&';

    // Loop through each character in the profile string
    for (size_t i = 0; i < inputLen; i++) {

        // Checking the use of '=' and '&': Cannot be too many and they must alternate in a valid string
        if (currentKv > 2 || prevSymbol == inputString[i]) {
            printf("Error: Invalid input string\n");
            free_key_value(object);
            return 1;
        }

        // If we find an equals sign ...
        if (inputString[i] == '=') {

            // Checks if parts of the profile are missing
            if (i - start == 0) {
                printf("Error: Invalid input string\n");
                free_key_value(object);
                return 1;
            }
            // ... then the letters we read must be a 'key' string
            object[currentKv].key = (char*)malloc((i - start + 1) * sizeof(char));
            if (object[currentKv].key == NULL) {
                printf("Error: Could not allocate memory\n");
                free_key_value(object);
                return 1;
            }
            // Copy the key string into the struct
            memcpy(object[currentKv].key, inputString + start, i - start);
            object[currentKv].key[i - start] = '\0';
            start = i + 1;

            // If on the last block, then will be a 'value' string to follow with no '&'
            if (currentKv == 2) {
                object[currentKv].value = (char*)malloc((inputLen - i) * sizeof(char));
                if (object[currentKv].value == NULL) {
                    printf("Error: Could not allocate memory\n");
                    free_key_value(object);
                    return 1;
                }
                // Copy the value string inot the struct
                memcpy(object[currentKv].value, inputString + start, inputLen - i - 1);
                object[currentKv].value[inputLen - i - 1] = '\0';
            }
            prevSymbol = '=';
        }

        // If we find a '&' symbol ...
        else if (inputString[i] == '&') {

            // Checks if parts of the profile are missing
            if (i - start == 0) {
                printf("Error: Invalid input string\n");
                free_key_value(object);
                return 1;
            }

            // ... then the letters we read must be a 'v' string
            object[currentKv].value = (char*)malloc((i - start + 1) * sizeof(char));
            if (object[currentKv].value == NULL) {
                printf("Error: Could not allocate memory\n");
                free_key_value(object);
                return 1;
            }

            // Copy the value string into the struct
            memcpy(object[currentKv].value, inputString + start, i - start);
            object[currentKv].value[i - start] = '\0';
            start = i + 1;
            currentKv++;
            prevSymbol = '&';
        }
    }

    return 0;
}

int create_key_value(struct kv* object)
{
    if (object == NULL) {
        return 1;
    }

    // Puts NULL in every slot
    for (size_t i = 0; i < 3; i++) {
        object[i].key = NULL;
        object[i].value = NULL;
    }
    return 0;
}

int free_key_value(struct kv* object)
{
    if (object == NULL) {
        return 1;
    }

    // Frees all the memory in an array of structs if required
    for (size_t i = 0; i < 3; i++) {
        if (object[i].key != NULL) {
            free(object[i].key);
            object[i].key = NULL;
        }
        if (object[i].value != NULL) {
            free(object[i].value);
            object[i].value = NULL;
        }
    }
    return 0;
}

int print_key_value(const struct kv* object)
{
    if (object == NULL) {
        return 1;
    }

    // Prints an array of structs in the desired format
    printf("{\n");
    printf("  %s: '%s',\n", object[0].key, object[0].value);
    printf("  %s: '%s',\n", object[1].key, object[1].value);
    printf("  %s: '%s'\n", object[2].key, object[2].value);
    printf("}\n");

    return 0;
}
