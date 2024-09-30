// my_aes_example.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <oqs/aes.h>

// Include OpenSSL headers for Base64 encoding
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

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
        return NULL;
    }

    // Copy the Base64 data to the new string
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0'; // Null-terminate the string

    // Clean up
    BIO_free_all(b64);

    return buff;
}

int main() {
    // Initialize liboqs
    OQS_init();

    // Define the plaintext "helloworld" and pad it to 16 bytes (AES block size)
    uint8_t plaintext[16] = {0};
    memcpy(plaintext, "helloworld", 10);

    // Define a 16-byte key for AES-128
    uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    // Buffer to hold the ciphertext
    uint8_t ciphertext[16];

    // Load AES-128 encryption schedule
    void *schedule = NULL;
    OQS_AES128_ECB_load_schedule(key, &schedule);

    // Encrypt the plaintext
    OQS_AES128_ECB_enc_sch(plaintext, sizeof(plaintext), schedule, ciphertext);

    // Encode the ciphertext in Base64
    char *ciphertext_b64 = base64_encode(ciphertext, sizeof(ciphertext));
    if (ciphertext_b64 == NULL) {
        fprintf(stderr, "Base64 encoding failed\n");
        OQS_AES128_free_schedule(schedule);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    // Print the plaintext, ciphertext, and key
    //printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext (Base64): %s\n", ciphertext_b64);
    printf("Key: ");
    for (size_t i = 0; i < sizeof(key); i++) {
        printf("%02X", key[i]);
    }
    printf("\n");

    // Free allocated resources
    free(ciphertext_b64);
    OQS_AES128_free_schedule(schedule);
    OQS_destroy();

    return EXIT_SUCCESS;
}
