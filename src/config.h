#ifndef CONFIG_H
#define CONFIG_H

#define DEFAULT_DB_PATH "password_manager.db"


/* Algorithmes */
#define HASH_ALGORITHM "SHA-256"
#define ENCRYPTION_ALGORITHM "AES-256-CBC"
#define KEY_DERIVATION_ALGORITHM "PBKDF2"

/* Paramètres de sécurité */
#define PBKDF2_ITERATIONS 100000  
#define AES_KEY_SIZE 32           // 256 bits
#define AES_IV_SIZE 16            // 128 bits

#define MIN_USERNAME_LENGTH 3
#define MIN_PASSWORD_LENGTH 8

#define SESSION_TIMEOUT_SECONDS 1800  // 30 minutes

#define MSG_WELCOME "\n=== Password Manager - Secure Vault ===\n"
#define MSG_GOODBYE "\nGoodbye! Stay secure.\n"

#define MSG_ERROR_INVALID_INPUT "Error: Invalid input\n"
#define MSG_ERROR_USER_EXISTS "Error: Username already exists\n"
#define MSG_ERROR_USER_NOT_FOUND "Error: User not found\n"
#define MSG_ERROR_AUTH_FAILED "Error: Authentication failed\n"
#define MSG_ERROR_WEAK_PASSWORD "Error: Password too weak (min 8 characters)\n"
#define MSG_ERROR_DB "Error: Database operation failed\n"
#define MSG_ERROR_CRYPTO "Error: Cryptographic operation failed\n"

#define MSG_SUCCESS_REGISTER "Success: Account created! You can now login.\n"
#define MSG_SUCCESS_LOGIN "Success: Welcome back!\n"
#define MSG_SUCCESS_LOGOUT "Success: Logged out.\n"
#define MSG_SUCCESS_PASSWORD_ADDED "Success: Password stored securely.\n"
#define MSG_SUCCESS_PASSWORD_DELETED "Success: Password deleted.\n"

//DEBUGGING
#ifdef DEBUG
#define DEBUG_PRINT(...) fprintf(stderr, "[DEBUG] " fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(...) do {} while(0)
#endif

#endif /* CONFIG_H */