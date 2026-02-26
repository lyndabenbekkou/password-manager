#include "auth.h"
#include "crypto.h"
#include "interface.h"
#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

static int auth_initialized = 0;

/*
 * Efface de manière sécurisée une zone mémoire
 */
static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *volatile_ptr = (volatile uint8_t *)ptr;
    while (len--) {
        *volatile_ptr++ = 0;
    }
}

/*
 * Initialise le système d'authentification
 */
int auth_init(void) {
    if (auth_initialized) {
        DEBUG_PRINT("Auth already initialized\n");
        return SUCCESS;
    }
    
    DEBUG_PRINT("Auth initialized successfully\n");
    auth_initialized = 1;
    return SUCCESS;
}

/*
 * Cleanup du module d'authentification
 */
void auth_cleanup(void) {
    if (!auth_initialized) {
        return;
    }
    
    DEBUG_PRINT("Auth cleaned up\n");
    auth_initialized = 0;
}

/*
 * Validatinon username (alphanum + underscore, 3-49 chars) et du password (min 8 chars TODO: renforcer)
 */

int auth_validate_username(const char *username) {
    if (!username) {
        return 0;
    }
    
    size_t len = strlen(username);
    
    if (len < MIN_USERNAME_LENGTH || len >= MAX_USERNAME_LENGTH) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        if (!isalnum(username[i]) && username[i] != '_') {
            return 0;
        }
    }
    
    return 1;
}

int auth_validate_password_strength(const char *password) {
    if (!password) {
        return 0;
    }
    
    size_t len = strlen(password);
    
    // Minimum 8 caractères
    if (len < MIN_PASSWORD_LENGTH) {
        fprintf(stderr, "❌ Password must be at least %d characters\n", MIN_PASSWORD_LENGTH);
        return 0;
    }
    
    // Vérifications : majuscule, minuscule, chiffre, caractère spécial
    int has_upper = 0;
    int has_lower = 0;
    int has_digit = 0;
    int has_special = 0;
    
    for (size_t i = 0; i < len; i++) {
        if (isupper(password[i])) has_upper = 1;
        else if (islower(password[i])) has_lower = 1;
        else if (isdigit(password[i])) has_digit = 1;
        else if (ispunct(password[i])) has_special = 1;
    }
    
    // Affichage des erreurs spécifiques
    if (!has_upper) {
        fprintf(stderr, "❌ Password must contain at least one uppercase letter (A-Z)\n");
        return 0;
    }
    if (!has_lower) {
        fprintf(stderr, "❌ Password must contain at least one lowercase letter (a-z)\n");
        return 0;
    }
    if (!has_digit) {
        fprintf(stderr, "❌ Password must contain at least one digit (0-9)\n");
        return 0;
    }
    if (!has_special) {
        fprintf(stderr, "❌ Password must contain at least one special character (!@#$%%^&*...)\n");
        return 0;
    }
    
    return 1;
}

/*
 * INSCRIPTION
 */

int auth_register(const char *username, const char *password) {
    
    if (!username || !password) {
        fprintf(stderr, "Error: Invalid parameters (NULL)\n");
        return ERROR_INVALID_PARAMS;
    }
    
    // Valide le nom d'utilisateur
    if (!auth_validate_username(username)) {
        fprintf(stderr, "Error: Invalid username (length or characters)\n");
        return ERROR_INVALID_PARAMS;
    }
    
    // Valide la force du mot de passe
    if (!auth_validate_password_strength(password)) {
        fprintf(stderr, "Error: Password too weak (minimum %d characters)\n", 
                MIN_PASSWORD_LENGTH);
        return ERROR_INVALID_PARAMS;
    }
    
    // Vérifie que l'utilisateur n'existe pas déjà
    User existing_user;
    int result = db_get_user_by_username(username, &existing_user);
    if (result == SUCCESS) {
        fprintf(stderr, "Error: Username already exists\n");
        return ERROR_USER_EXISTS;
    }
    
    char salt[SALT_LENGTH];
    if (crypto_generate_salt(salt) != SUCCESS) {
        fprintf(stderr, "Error: Failed to generate salt\n");
        return ERROR_CRYPTO;
    }
    
    // Hache le mot de passe avec le sel
    char password_hash[HASH_LENGTH];
    if (crypto_hash_password(password, salt, password_hash) != SUCCESS) {
        fprintf(stderr, "Error: Failed to hash password\n");
        return ERROR_CRYPTO;
    }
    
    // Crée l'utilisateur dans la base de données
    int user_id = db_create_user(username, password_hash, salt);
    if (user_id < 0) {
        fprintf(stderr, "Error: Failed to create user in database\n");
        return ERROR_DB;
    }
    
    // Nettoie les données sensibles
    secure_zero(password_hash, sizeof(password_hash));
    
    DEBUG_PRINT("User registered successfully (ID: %d, Username: %s)\n", 
                user_id, username);
    return SUCCESS;
}

/**
 * CONNEXION
 */

int auth_login(const char *username, const char *password, Session *session) {
    
    if (!username || !password || !session) {
        fprintf(stderr, "Error: Invalid parameters i ULL)\n");
        return ERROR_INVALID_PARAMS;
    }
    
    User user;
    int result = db_get_user_by_username(username, &user);
    if (result != SUCCESS) {
        fprintf(stderr, "Error: User not found\n");
        char dummy_salt[SALT_LENGTH] = "0000000000000000000000000000000";
        char dummy_hash[HASH_LENGTH];
        crypto_hash_password("dummy", dummy_salt, dummy_hash);
        return ERROR_AUTH_FAILED;
    }
    
    char computed_hash[HASH_LENGTH];
    if (crypto_hash_password(password, user.salt, computed_hash) != SUCCESS) {
        fprintf(stderr, "Error: Failed to hash password\n");
        return ERROR_CRYPTO;
    }
    
    if (strcmp(computed_hash, user.password_hash) != 0) {
        fprintf(stderr, "Error: Authentication failed (wrong password)\n");
        secure_zero(computed_hash, sizeof(computed_hash));
        return ERROR_AUTH_FAILED;
    }
    
    secure_zero(computed_hash, sizeof(computed_hash));
    
    session->user_id = user.user_id;
    strncpy(session->username, user.username, MAX_USERNAME_LENGTH - 1);
    session->username[MAX_USERNAME_LENGTH - 1] = '\0';
    session->is_authenticated = 1;
    session->session_start = time(NULL);
    
    
    if (crypto_derive_key(password, user.salt, session->master_key) != SUCCESS) {
        fprintf(stderr, "Error: Failed to derive master key\n");
        auth_logout(session);
        return ERROR_CRYPTO;
    }
    
    db_update_last_login(user.user_id);
    
    DEBUG_PRINT("User logged in successfully (ID: %d, Username: %s)\n", 
                user.user_id, user.username);
    return SUCCESS;
}

/**
 *  DÉCONNEXION
 */

void auth_logout(Session *session) {
    if (!session) {
        return;
    }
    
    DEBUG_PRINT("Logging out user (ID: %d, Username: %s)\n", 
                session->user_id, session->username);
    
    secure_zero(session->master_key, sizeof(session->master_key));
    secure_zero(session->username, sizeof(session->username));
    
    session->user_id = 0;
    session->is_authenticated = 0;
    session->session_start = 0;
}

/**
 * Validation de la session
 */
int auth_is_session_valid(const Session *session) {
    if (!session) {
        return 0;
    }
    
    if (!session->is_authenticated) {
        return 0;
    }
    
    if (session->user_id <= 0) {
        return 0;
    }
    
    time_t now = time(NULL);
    time_t elapsed = now - session->session_start;
    
    if (elapsed > SESSION_TIMEOUT_SECONDS) {
        DEBUG_PRINT("Session expired (elapsed: %ld seconds)\n", elapsed);
        return 0;
    }
    
    return 1;
}

/*
 * Change le mot de passe maître et re-chiffre tous les mots de passe stockés
 */
int auth_change_master_password(Session *session, const char *old_password, const char *new_password) {
    if (!session || !old_password || !new_password) {
        fprintf(stderr, "Error: Invalid parameters (NULL)\n");
        return ERROR_INVALID_PARAMS;
    }
    
    // Vérification que la session est valide
    if (!auth_is_session_valid(session)) {
        fprintf(stderr, "Error: Session expired or invalid\n");
        return ERROR_AUTH_FAILED;
    }
    
    // Validation du nouveau mot de passe
    if (!auth_validate_password_strength(new_password)) {
        return ERROR_INVALID_PARAMS;
    }
    
    // Récupération des infos utilisateur depuis la base
    User user;
    int result = db_get_user_by_id(session->user_id, &user);
    if (result != SUCCESS) {
        fprintf(stderr, "Error: Failed to retrieve user data\n");
        return ERROR_DB;
    }
    
    // Vérification de l'ancien mot de passe
    char computed_hash[HASH_LENGTH];
    if (crypto_hash_password(old_password, user.salt, computed_hash) != SUCCESS) {
        fprintf(stderr, "Error: Failed to hash old password\n");
        return ERROR_CRYPTO;
    }
    
    if (strcmp(computed_hash, user.password_hash) != 0) {
        fprintf(stderr, "Error: Old password incorrect\n");
        secure_zero(computed_hash, sizeof(computed_hash));
        return ERROR_AUTH_FAILED;
    }
    secure_zero(computed_hash, sizeof(computed_hash));
    
    // Génération du nouveau sel
    char new_salt[SALT_LENGTH];
    if (crypto_generate_salt(new_salt) != SUCCESS) {
        fprintf(stderr, "Error: Failed to generate new salt\n");
        return ERROR_CRYPTO;
    }
    
    // Hachage du nouveau mot de passe
    char new_password_hash[HASH_LENGTH];
    if (crypto_hash_password(new_password, new_salt, new_password_hash) != SUCCESS) {
        fprintf(stderr, "Error: Failed to hash new password\n");
        return ERROR_CRYPTO;
    }
    
    // Dérivation de la nouvelle clé maître
    uint8_t new_master_key[32];
    if (crypto_derive_key(new_password, new_salt, new_master_key) != SUCCESS) {
        fprintf(stderr, "Error: Failed to derive new master key\n");
        secure_zero(new_password_hash, sizeof(new_password_hash));
        return ERROR_CRYPTO;
    }
    
    // Récupération de tous les mots de passe de l'utilisateur
    PasswordEntry *entries = NULL;
    int count = 0;
    result = db_get_user_passwords(session->user_id, &entries, &count);
    if (result != SUCCESS) {
        fprintf(stderr, "Error: Failed to retrieve password entries\n");
        secure_zero(new_master_key, sizeof(new_master_key));
        secure_zero(new_password_hash, sizeof(new_password_hash));
        return ERROR_DB;
    }
    
    // Re-chiffrement de tous les mots de passe
    for (int i = 0; i < count; i++) {
        char plaintext[MAX_PASSWORD_LENGTH];
        
        // Déchiffrement avec l'ancienne clé (dans la session)
        result = crypto_decrypt_password(entries[i].encrypted_password, 
                                        session->master_key, 
                                        entries[i].iv, 
                                        plaintext);
        
        if (result != SUCCESS) {
            fprintf(stderr, "Error: Failed to decrypt password entry %d\n", entries[i].entry_id);
            secure_zero(plaintext, sizeof(plaintext));
            free(entries);
            secure_zero(new_master_key, sizeof(new_master_key));
            secure_zero(new_password_hash, sizeof(new_password_hash));
            return ERROR_CRYPTO;
        }
        
        // Re-chiffrement avec la nouvelle clé
        char new_encrypted[MAX_ENCRYPTED_LENGTH];
        char new_iv[33];
        result = crypto_encrypt_password(plaintext, new_master_key, new_encrypted, new_iv);
        
        // Nettoyage du mot de passe en clair
        secure_zero(plaintext, sizeof(plaintext));
        
        if (result != SUCCESS) {
            fprintf(stderr, "Error: Failed to re-encrypt password entry %d\n", entries[i].entry_id);
            free(entries);
            secure_zero(new_master_key, sizeof(new_master_key));
            secure_zero(new_password_hash, sizeof(new_password_hash));
            return ERROR_CRYPTO;
        }
        
        // Mise à jour de l'entrée
        strncpy(entries[i].encrypted_password, new_encrypted, MAX_ENCRYPTED_LENGTH - 1);
        entries[i].encrypted_password[MAX_ENCRYPTED_LENGTH - 1] = '\0';
        strncpy(entries[i].iv, new_iv, 32);
        entries[i].iv[32] = '\0';
        
        // Sauvegarde en base
        result = db_update_password(&entries[i]);
        if (result != SUCCESS) {
            fprintf(stderr, "Error: Failed to update password entry %d in database\n", entries[i].entry_id);
            free(entries);
            secure_zero(new_master_key, sizeof(new_master_key));
            secure_zero(new_password_hash, sizeof(new_password_hash));
            return ERROR_DB;
        }
    }
    
    // Libération de la mémoire
    free(entries);
    
    // Mise à jour du mot de passe maître en base
    result = db_update_user_password(session->user_id, new_password_hash, new_salt);
    secure_zero(new_password_hash, sizeof(new_password_hash));
    
    if (result != SUCCESS) {
        fprintf(stderr, "Error: Failed to update master password in database\n");
        secure_zero(new_master_key, sizeof(new_master_key));
        return ERROR_DB;
    }
    
    // Mise à jour de la clé maître dans la session
    memcpy(session->master_key, new_master_key, sizeof(session->master_key));
    secure_zero(new_master_key, sizeof(new_master_key));
    
    DEBUG_PRINT("Master password changed successfully for user %d\n", session->user_id);
    return SUCCESS;
}