#include "crypto.h"
#include "config.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

// Convertit un tableau de bytes en chaîne hexadécimale
void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

// Convertit une chaîne hexadécimale en tableau de bytes
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t *bytes_len) {
    if (!hex || !bytes || !bytes_len) {
        return ERROR_INVALID_PARAMS;
    }
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return ERROR_CRYPTO;
    }
    
    *bytes_len = hex_len / 2;
    
    for (size_t i = 0; i < *bytes_len; i++) {
        if (sscanf(hex + (i * 2), "%2hhx", &bytes[i]) != 1) {
            return ERROR_CRYPTO;
        }
    }
    
    return SUCCESS;
}

// Efface une zone mémoire de manière sécurisée
static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *volatile_ptr = (volatile uint8_t *)ptr;
    while (len--) {
        *volatile_ptr++ = 0;
    }
}

// Initialise les modules cryptographiques d'OpenSSL
int crypto_init(void) {
    #if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    #endif
    
    if (RAND_status() != 1) {
        fprintf(stderr, "Error: OpenSSL PRNG not seeded\n");
        return ERROR_CRYPTO;
    }
    
    DEBUG_PRINT("Crypto initialized successfully\n");
    return SUCCESS;
}

// Libère les ressources OpenSSL si nécessaire
void crypto_cleanup(void) {
    #if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    ERR_free_strings();
    #endif
    
    DEBUG_PRINT("Crypto cleaned up\n");
}

// Génère un sel aléatoire sous forme hexadécimale
int crypto_generate_salt(char *salt) {
    if (!salt) {
        return ERROR_INVALID_PARAMS;
    }
    
    uint8_t salt_bytes[16];
    
    if (RAND_bytes(salt_bytes, sizeof(salt_bytes)) != 1) {
        fprintf(stderr, "Error: Failed to generate random salt\n");
        return ERROR_CRYPTO;
    }
    
    bytes_to_hex(salt_bytes, sizeof(salt_bytes), salt);
    
    DEBUG_PRINT("Generated salt: %s\n", salt);
    return SUCCESS;
}

// Hache un mot de passe avec SHA-256 + sel
int crypto_hash_password(const char *password, const char *salt, char *hash) {
    if (!password || !salt || !hash) {
        return ERROR_INVALID_PARAMS;
    }
    
    char combined[MAX_PASSWORD_LENGTH + SALT_LENGTH];
    snprintf(combined, sizeof(combined), "%s%s", password, salt);
    
    uint8_t hash_bytes[SHA256_DIGEST_LENGTH];
    SHA256((const uint8_t *)combined, strlen(combined), hash_bytes);
    
    bytes_to_hex(hash_bytes, SHA256_DIGEST_LENGTH, hash);
    
    secure_zero(combined, sizeof(combined));
    
    DEBUG_PRINT("Password hashed successfully\n");
    return SUCCESS;
}

// Dérive une clé AES-256 avec PBKDF2-HMAC-SHA256
int crypto_derive_key(const char *password, const char *salt, uint8_t *key) {
    if (!password || !salt || !key) {
        return ERROR_INVALID_PARAMS;
    }
    
    uint8_t salt_bytes[16];
    size_t salt_len;
    if (hex_to_bytes(salt, salt_bytes, &salt_len) != SUCCESS) {
        return ERROR_CRYPTO;
    }
    
    if (PKCS5_PBKDF2_HMAC(
        password, strlen(password),
        salt_bytes, salt_len,
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        AES_KEY_SIZE,
        key
    ) != 1) {
        fprintf(stderr, "Error: PBKDF2 key derivation failed\n");
        return ERROR_CRYPTO;
    }
    
    DEBUG_PRINT("Key derived successfully (%d iterations)\n", PBKDF2_ITERATIONS);
    return SUCCESS;
}

// Chiffre un mot de passe avec AES-256-CBC
int crypto_encrypt_password(const char *plaintext, const uint8_t *key, 
                            char *ciphertext, char *iv) {
    if (!plaintext || !key || !ciphertext || !iv) {
        return ERROR_INVALID_PARAMS;
    }
    
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t iv_bytes[AES_IV_SIZE];
    uint8_t encrypted[MAX_PASSWORD_LENGTH + AES_IV_SIZE];
    int len, ciphertext_len;
    
    if (RAND_bytes(iv_bytes, AES_IV_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate IV\n");
        return ERROR_CRYPTO;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        return ERROR_CRYPTO;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv_bytes) != 1) {
        fprintf(stderr, "Error: Encryption init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    
    if (EVP_EncryptUpdate(ctx, encrypted, &len, 
                         (const uint8_t *)plaintext, strlen(plaintext)) != 1) {
        fprintf(stderr, "Error: Encryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, encrypted + len, &len) != 1) {
        fprintf(stderr, "Error: Encryption final failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    ciphertext_len += len;
    
    bytes_to_hex(encrypted, ciphertext_len, ciphertext);
    bytes_to_hex(iv_bytes, AES_IV_SIZE, iv);
    
    EVP_CIPHER_CTX_free(ctx);
    secure_zero(encrypted, sizeof(encrypted));
    
    DEBUG_PRINT("Password encrypted successfully (length: %d)\n", ciphertext_len);
    return SUCCESS;
}

// Déchiffre un mot de passe chiffré avec AES-256-CBC
int crypto_decrypt_password(const char *ciphertext, const uint8_t *key,
                            const char *iv, char *plaintext) {
    if (!ciphertext || !key || !iv || !plaintext) {
        return ERROR_INVALID_PARAMS;
    }
    
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t iv_bytes[AES_IV_SIZE];
    uint8_t encrypted[MAX_ENCRYPTED_LENGTH / 2];
    uint8_t decrypted[MAX_PASSWORD_LENGTH];
    size_t encrypted_len, iv_len;
    int len, plaintext_len;
    
    if (hex_to_bytes(iv, iv_bytes, &iv_len) != SUCCESS || iv_len != AES_IV_SIZE) {
        fprintf(stderr, "Error: Invalid IV format\n");
        return ERROR_CRYPTO;
    }
    
    if (hex_to_bytes(ciphertext, encrypted, &encrypted_len) != SUCCESS) {
        fprintf(stderr, "Error: Invalid ciphertext format\n");
        return ERROR_CRYPTO;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        return ERROR_CRYPTO;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv_bytes) != 1) {
        fprintf(stderr, "Error: Decryption init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    
    if (EVP_DecryptUpdate(ctx, decrypted, &len, encrypted, encrypted_len) != 1) {
        fprintf(stderr, "Error: Decryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1) {
        fprintf(stderr, "Error: Decryption final failed (wrong key or corrupted data)\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    plaintext_len += len;
    
    memcpy(plaintext, decrypted, plaintext_len);
    plaintext[plaintext_len] = '\0';
    
    EVP_CIPHER_CTX_free(ctx);
    secure_zero(decrypted, sizeof(decrypted));
    secure_zero(encrypted, sizeof(encrypted));
    
    DEBUG_PRINT("Password decrypted successfully (length: %d)\n", plaintext_len);
    return SUCCESS;
}

/*
 * Chiffre les métadonnées (service_name, username)
 * Identique à crypto_encrypt_password mais avec un nom différent pour clarté
 */
int crypto_encrypt_metadata(const char *plaintext, const uint8_t *key, 
                            char *ciphertext, char *iv) {
    if (!plaintext || !key || !ciphertext || !iv) {
        return ERROR_INVALID_PARAMS;
    }
    
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t iv_bytes[AES_IV_SIZE];
    uint8_t encrypted[MAX_PASSWORD_LENGTH + AES_IV_SIZE];
    int len, ciphertext_len;
    
    if (RAND_bytes(iv_bytes, AES_IV_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate IV for metadata\n");
        return ERROR_CRYPTO;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        return ERROR_CRYPTO;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv_bytes) != 1) {
        fprintf(stderr, "Error: Metadata encryption init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    
    if (EVP_EncryptUpdate(ctx, encrypted, &len, 
                         (const uint8_t *)plaintext, strlen(plaintext)) != 1) {
        fprintf(stderr, "Error: Metadata encryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, encrypted + len, &len) != 1) {
        fprintf(stderr, "Error: Metadata encryption final failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    ciphertext_len += len;
    
    bytes_to_hex(encrypted, ciphertext_len, ciphertext);
    bytes_to_hex(iv_bytes, AES_IV_SIZE, iv);
    
    EVP_CIPHER_CTX_free(ctx);
    secure_zero(encrypted, sizeof(encrypted));
    
    DEBUG_PRINT("Metadata encrypted successfully\n");
    return SUCCESS;
}

/*
 * Déchiffre les métadonnées (service_name, username)
 */
int crypto_decrypt_metadata(const char *ciphertext, const uint8_t *key,
                            const char *iv, char *plaintext, size_t plaintext_size) {
    if (!ciphertext || !key || !iv || !plaintext) {
        return ERROR_INVALID_PARAMS;
    }
    
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t iv_bytes[AES_IV_SIZE];
    uint8_t encrypted[MAX_ENCRYPTED_LENGTH / 2];
    uint8_t decrypted[MAX_PASSWORD_LENGTH];
    size_t encrypted_len, iv_len;
    int len, plaintext_len;
    
    if (hex_to_bytes(iv, iv_bytes, &iv_len) != SUCCESS || iv_len != AES_IV_SIZE) {
        fprintf(stderr, "Error: Invalid IV format for metadata\n");
        return ERROR_CRYPTO;
    }
    
    if (hex_to_bytes(ciphertext, encrypted, &encrypted_len) != SUCCESS) {
        fprintf(stderr, "Error: Invalid ciphertext format for metadata\n");
        return ERROR_CRYPTO;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        return ERROR_CRYPTO;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv_bytes) != 1) {
        fprintf(stderr, "Error: Metadata decryption init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    
    if (EVP_DecryptUpdate(ctx, decrypted, &len, encrypted, encrypted_len) != 1) {
        fprintf(stderr, "Error: Metadata decryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1) {
        fprintf(stderr, "Error: Metadata decryption final failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    plaintext_len += len;
    
    if ((size_t)plaintext_len >= plaintext_size) {
        fprintf(stderr, "Error: Decrypted metadata too large\n");
        EVP_CIPHER_CTX_free(ctx);
        return ERROR_CRYPTO;
    }
    
    memcpy(plaintext, decrypted, plaintext_len);
    plaintext[plaintext_len] = '\0';
    
    EVP_CIPHER_CTX_free(ctx);
    secure_zero(decrypted, sizeof(decrypted));
    secure_zero(encrypted, sizeof(encrypted));
    
    DEBUG_PRINT("Metadata decrypted successfully\n");
    return SUCCESS;
}