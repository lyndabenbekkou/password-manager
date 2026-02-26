#ifndef CRYPTO_H
#define CRYPTO_H
#include "common.h"
#include <stdint.h>

int crypto_init(void);
void crypto_cleanup(void);
int crypto_generate_salt(char *salt);
int crypto_hash_password(const char *password, const char *salt, char *hash);
int crypto_derive_key(const char *password, const char *salt, uint8_t *key);
int crypto_encrypt_password(const char *plaintext, const uint8_t *key, char *ciphertext, char *iv);
int crypto_decrypt_password(const char *ciphertext, const uint8_t *key, const char *iv, char *plaintext);

// ← AJOUTEZ CES DEUX LIGNES
int crypto_encrypt_metadata(const char *plaintext, const uint8_t *key, char *ciphertext, char *iv);
int crypto_decrypt_metadata(const char *ciphertext, const uint8_t *key, const char *iv, char *plaintext, size_t plaintext_size);

void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex);
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t *bytes_len);

#endif /* CRYPTO_H */