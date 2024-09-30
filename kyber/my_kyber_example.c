// kyber_aes_example.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

// Include OpenSSL headers
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

#define MESSAGE "Hello, Quantum World!"

/* Function to print hexadecimal strings */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (Hex):", label);
    for (size_t i = 0; i < len; i++) {
        printf(" %02X", data[i]);
    }
    printf("\n");
}

/* Function to print the data as a string */
void print_as_string(const char *label, const uint8_t *data, size_t len) {
    printf("%s (String): ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%c", data[i]);
    }
    printf("\n");
}

/* Function to encode data in Base64 */
char *base64_encode(const uint8_t *input, int length) {
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;

    // Create a BIO filter for Base64 encoding
    b64 = BIO_new(BIO_f_base64());
    // Create a BIO memory buffer
    bmem = BIO_new(BIO_s_mem());
    // Chain the Base64 filter and the memory buffer
    b64 = BIO_push(b64, bmem);

    // Disable line breaks in the output
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // Write the input data to the BIO chain
    BIO_write(b64, input, length);
    BIO_flush(b64);

    // Get a pointer to the memory buffer's data
    BIO_get_mem_ptr(b64, &bptr);

    // Allocate a new string to hold the Base64 data
    char *buff = (char *)malloc(bptr->length + 1);
    if (buff == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        BIO_free_all(b64);
        return NULL;
    }

    // Copy the Base64 data to the new string
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0'; // Null-terminate the string

    // Clean up
    BIO_free_all(b64);

    return buff;
}

/* Function to encrypt data using AES-256-CBC */
int aes_encrypt(const uint8_t *plaintext, int plaintext_len, const uint8_t *key,
                uint8_t *iv, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Initialize the encryption operation with AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Encrypt the plaintext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/* Function to decrypt data using AES-256-CBC */
int aes_decrypt(const uint8_t *ciphertext, int ciphertext_len, const uint8_t *key,
                uint8_t *iv, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Initialize the decryption operation with AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        // If decryption fails, this function returns 0
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main() {
    // Initialize liboqs
    OQS_init();

    // Initialize OpenSSL algorithms
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Select the Kyber KEM algorithm
    const char *alg_name = OQS_KEM_alg_kyber_768;
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (kem == NULL) {
        fprintf(stderr, "ERROR: KEM %s not found.\n", alg_name);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    printf("Kyber KEM Hybrid Encryption Example - Algorithm: %s\n", alg_name);

    // Allocate memory for keys, ciphertext, and shared secrets
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_encap = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_decap = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !kem_ciphertext || !shared_secret_encap || !shared_secret_decap) {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        goto cleanup;
    }

    // Generate key pair
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Key pair generation failed.\n");
        goto cleanup;
    }
    printf("Key pair generated.\n");

    // Encapsulate to get shared secret and ciphertext
    if (OQS_KEM_encaps(kem, kem_ciphertext, shared_secret_encap, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Encapsulation failed.\n");
        goto cleanup;
    }
    printf("Encapsulation completed.\n");

    // Print the shared secret generated during encapsulation (both hex and string)
    //print_hex("Shared Secret (Generated during Encapsulation)", shared_secret_encap, kem->length_shared_secret);
    print_as_string("Shared Secret (Generated during Encapsulation)", shared_secret_encap, kem->length_shared_secret);

    // Print the ciphertext that would be sent across the network (both hex and string)
    //print_hex("Ciphertext (Encapsulated form sent over network)", kem_ciphertext, kem->length_ciphertext);
    print_as_string("Ciphertext (Encapsulated form sent over network)", kem_ciphertext, kem->length_ciphertext);

    // Decapsulate to get shared secret
    if (OQS_KEM_decaps(kem, shared_secret_decap, kem_ciphertext, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Decapsulation failed.\n");
        goto cleanup;
    }
    printf("Decapsulation completed.\n");

    // Print the shared secret after decapsulation (both hex and string)
    print_hex("Shared Secret (Recovered during Decapsulation)", shared_secret_decap, kem->length_shared_secret);
    print_as_string("Shared Secret (Recovered during Decapsulation)", shared_secret_decap, kem->length_shared_secret);

    // Verify that the shared secrets match
    if (memcmp(shared_secret_encap, shared_secret_decap, kem->length_shared_secret) != 0) {
        fprintf(stderr, "ERROR: Shared secrets do not match.\n");
        goto cleanup;
    }
    printf("Shared secrets match.\n");

    // Prepare the message for encryption
    size_t message_len = strlen(MESSAGE);

    // Initialize IV (Initialization Vector) with zeros (not secure, for demonstration)
    uint8_t iv[16] = {0};

    // Encrypt the message using the shared secret as the AES key
    int ciphertext_len;
    uint8_t *aes_ciphertext = malloc(message_len + 16); // Extra space for padding
    if ((ciphertext_len = aes_encrypt((uint8_t *)MESSAGE, message_len, shared_secret_encap, iv, aes_ciphertext)) == -1) {
        fprintf(stderr, "ERROR: AES encryption failed.\n");
        goto cleanup;
    }

    // Encode the AES ciphertext in Base64 for display
    char *aes_ciphertext_b64 = base64_encode(aes_ciphertext, ciphertext_len);
    if (aes_ciphertext_b64 == NULL) {
        fprintf(stderr, "ERROR: Base64 encoding failed.\n");
        goto cleanup;
    }

    // Print the original message and the AES ciphertext
    printf("Original Message: %s\n", MESSAGE);
    printf("AES Encrypted Message (Base64): %s\n", aes_ciphertext_b64);

    // Decrypt the AES ciphertext using the shared secret
    uint8_t *decrypted_plaintext = malloc(ciphertext_len);
    int decrypted_len;
    if ((decrypted_len = aes_decrypt(aes_ciphertext, ciphertext_len, shared_secret_decap, iv, decrypted_plaintext)) == -1) {
        fprintf(stderr, "ERROR: AES decryption failed.\n");
        goto cleanup;
    }

    // Null-terminate the decrypted plaintext
    decrypted_plaintext[decrypted_len] = '\0';

    // Print the decrypted message
    printf("Decrypted Message: %s\n", decrypted_plaintext);

    // Success
    printf("SUCCESS: The message was encrypted and decrypted successfully using the shared secret from Kyber KEM.\n");

cleanup:
    // Free allocated memory and clean up
    if (public_key) OQS_MEM_insecure_free(public_key);
    if (secret_key) OQS_MEM_secure_free(secret_key, kem->length_secret_key);
    if (kem_ciphertext) OQS_MEM_insecure_free(kem_ciphertext);
    if (shared_secret_encap) OQS_MEM_secure_free(shared_secret_encap, kem->length_shared_secret);
    if (shared_secret_decap) OQS_MEM_secure_free(shared_secret_decap, kem->length_shared_secret);
    if (aes_ciphertext) free(aes_ciphertext);
    if (aes_ciphertext_b64) free(aes_ciphertext_b64);
    if (decrypted_plaintext) free(decrypted_plaintext);

    OQS_KEM_free(kem);
    OQS_destroy();

    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return EXIT_SUCCESS;
}
