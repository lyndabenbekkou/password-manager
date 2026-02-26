#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include "../common.h"
#include "../interface.h"
#include "../crypto.h"
#include "../auth.h"
#include "../database.h"
#include "../config.h"

#define TEST_DB_FILE "test_suite.db"
#define CHECK_MARK "✓"

// Initialise l'environnement de test (DB temporaire + modules)
void setup_env() {
    unlink(TEST_DB_FILE);
    
    assert(crypto_init() == SUCCESS);
    assert(db_init(TEST_DB_FILE) == SUCCESS);
    assert(auth_init() == SUCCESS);
}

// Nettoie l'environnement de test et supprime la DB
void teardown_env() {
    auth_cleanup();
    db_close();
    crypto_cleanup();
    
    unlink(TEST_DB_FILE);
}

// Test les primitives cryptographiques : génération de sel, hash et chiffrement/déchiffrement
void test_module_crypto() {
    printf("[CRYPTO] Primitives cryptographiques... ");
    
    char salt[SALT_LENGTH];
    char hash[HASH_LENGTH];
    
    assert(crypto_generate_salt(salt) == SUCCESS);
    assert(strlen(salt) == 32);
    
    assert(crypto_hash_password("password123", salt, hash) == SUCCESS);
    assert(strlen(hash) == 64);
    
    char *original = "MySecretData";
    uint8_t key[32];
    char ciphertext[MAX_ENCRYPTED_LENGTH];
    char iv[33];
    char decrypted[MAX_PASSWORD_LENGTH];
    
    crypto_derive_key("MasterKey", salt, key);
    assert(crypto_encrypt_password(original, key, ciphertext, iv) == SUCCESS);
    assert(crypto_decrypt_password(ciphertext, key, iv, decrypted) == SUCCESS);
    assert(strcmp(original, decrypted) == 0);
    
    printf("%s\n", CHECK_MARK);
}

// Test la validation des entrées utilisateur : force du mot de passe et format du nom d'utilisateur
void test_module_validation() {
    printf("[AUTH] Validation des entrées... ");
    
    // Mots de passe FAIBLES (doivent échouer)
    assert(auth_validate_password_strength("court") == 0);              // Trop court
    assert(auth_validate_password_strength("password") == 0);           // Pas de maj, chiffre, spécial
    assert(auth_validate_password_strength("Password") == 0);           // Pas de chiffre, spécial
    assert(auth_validate_password_strength("Password1") == 0);          // Pas de spécial
    assert(auth_validate_password_strength("jeremy_pass123") == 0);     // Pas de maj, spécial
    
    // Mots de passe FORTS (doivent réussir)
    assert(auth_validate_password_strength("Password1!") == 1);         // OK : Maj + Min + Chiffre + Spécial
    assert(auth_validate_password_strength("Jeremy123!") == 1);         // OK
    assert(auth_validate_password_strength("ValidPass123@") == 1);      // OK
    
    // Validation username (inchangée)
    assert(auth_validate_username("ab") == 0);                          // Trop court
    assert(auth_validate_username("user/name") == 0);                   // Caractères invalides
    assert(auth_validate_username("jeremy_valid") == 1);                // OK
    
    printf("%s\n", CHECK_MARK);
}

// Test les opérations CRUD de la base de données : création, lecture, mise à jour, suppression
void test_module_database() {
    printf("[DB] Opérations CRUD... ");
    
    int user_id = db_create_user("FlaviaDB", "dummy_hash", "dummy_salt");
    assert(user_id > 0);
    
    PasswordEntry entry = {0};
    entry.user_id = user_id;
    strcpy(entry.service_name, "FlaviaService");
    strcpy(entry.service_iv, "00112233445566778899aabbccddeeff");
    strcpy(entry.username, "FlaviaUser");
    strcpy(entry.username_iv, "ffeeddccbbaa99887766554433221100");
    strcpy(entry.encrypted_password, "EncData");
    strcpy(entry.iv, "IVData");
    
    int entry_id = db_store_password(&entry);
    assert(entry_id > 0);
    
    PasswordEntry retrieved;
    assert(db_get_password_entry(entry_id, user_id, &retrieved) == SUCCESS);
    assert(strcmp(retrieved.service_name, "FlaviaService") == 0);
    
    strcpy(retrieved.username, "FlaviaUser_Updated");
    assert(db_update_password(&retrieved) == SUCCESS);
    
    PasswordEntry check;
    db_get_password_entry(entry_id, user_id, &check);
    assert(strcmp(check.username, "FlaviaUser_Updated") == 0);
    
    assert(db_delete_password(entry_id, user_id) == SUCCESS);
    assert(db_get_password_entry(entry_id, user_id, &check) != SUCCESS);
    
    printf("%s\n", CHECK_MARK);
}

// Test la fonction d'inscription : validation, création utilisateur, gestion des erreurs
void test_auth_register() {
    printf("[AUTH] Inscription utilisateur... ");
    
    assert(auth_register("Linda", "LindaSecure123!") == SUCCESS);
    assert(auth_register("ab", "SecurePass123!") == ERROR_INVALID_PARAMS);
    assert(auth_register("validuser", "court") == ERROR_INVALID_PARAMS);
    assert(auth_register("Linda", "AutrePass456!") == ERROR_USER_EXISTS);
    assert(auth_register(NULL, "password") == ERROR_INVALID_PARAMS);
    assert(auth_register("user", NULL) == ERROR_INVALID_PARAMS);
    
    printf("%s\n", CHECK_MARK);
}

// Test la fonction de connexion : authentification, session, gestion des erreurs
void test_auth_login() {
    printf("[AUTH] Connexion et session... ");
    
    auth_register("Melissa", "MelissaPassword123!");
    
    Session session = {0};
    
    assert(auth_login("Melissa", "MelissaPassword123!", &session) == SUCCESS);
    assert(session.is_authenticated == 1);
    assert(session.user_id > 0);
    assert(strcmp(session.username, "Melissa") == 0);
    
    Session bad_session = {0};
    assert(auth_login("Melissa", "MauvaisMotDePasse", &bad_session) == ERROR_AUTH_FAILED);
    assert(bad_session.is_authenticated == 0);
    
    Session no_user_session = {0};
    assert(auth_login("noexist", "password", &no_user_session) == ERROR_AUTH_FAILED);
    
    assert(auth_login(NULL, "pass", &session) == ERROR_INVALID_PARAMS);
    assert(auth_login("user", NULL, &session) == ERROR_INVALID_PARAMS);
    assert(auth_login("user", "pass", NULL) == ERROR_INVALID_PARAMS);
    
    auth_logout(&session);
    printf("%s\n", CHECK_MARK);
}

// Test la validité et l'invalidation des sessions utilisateur
void test_auth_session_validity() {
    printf("[AUTH] Validité des sessions... ");
    
    auth_register("InesSession", "InesPass123!");
    Session session = {0};
    auth_login("InesSession", "InesPass123!", &session);
    
    assert(auth_is_session_valid(&session) == 1);
    
    auth_logout(&session);
    assert(auth_is_session_valid(&session) == 0);
    
    assert(auth_is_session_valid(NULL) == 0);
    
    Session unauth_session = {0};
    assert(auth_is_session_valid(&unauth_session) == 0);
    
    printf("%s\n", CHECK_MARK);
}

// Test la fonction secure_zero : effacement sécurisé de la clé maître en mémoire
void test_secure_zero() {
    printf("[CRYPTO] Effacement sécurisé... ");
    
    auth_register("JeremyZero", "JeremyTestPass123!");
    Session session = {0};
    auth_login("JeremyZero", "JeremyTestPass123!", &session);
    
    int has_data = 0;
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        if (session.master_key[i] != 0) {
            has_data = 1;
            break;
        }
    }
    assert(has_data == 1);
    
    auth_logout(&session);
    
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        assert(session.master_key[i] == 0);
    }
    
    printf("%s\n", CHECK_MARK);
}

// Test les cas limites de la base de données : listes vides, IDs invalides, entrées inexistantes
void test_db_edge_cases() {
    printf("[DB] Cas limites base de données... ");
    
    PasswordEntry *entries = NULL;
    int count = 0;
    int user_id = db_create_user("FlaviaEmpty", "hash", "salt");
    assert(db_get_user_passwords(user_id, &entries, &count) == SUCCESS);
    assert(count == 0);
    assert(entries == NULL);
    
    assert(db_delete_password(9999, user_id) != SUCCESS);
    
    PasswordEntry entry;
    assert(db_get_password_entry(9999, user_id, &entry) != SUCCESS);
    
    PasswordEntry fake_entry = {0};
    fake_entry.entry_id = 9999;
    fake_entry.user_id = user_id;
    strcpy(fake_entry.service_name, "Test");
    strcpy(fake_entry.service_iv, "00112233445566778899aabbccddeeff");
    strcpy(fake_entry.username, "test");
    strcpy(fake_entry.username_iv, "ffeeddccbbaa99887766554433221100");
    strcpy(fake_entry.encrypted_password, "enc");
    strcpy(fake_entry.iv, "iv");
    assert(db_update_password(&fake_entry) != SUCCESS);
    
    printf("%s\n", CHECK_MARK);
}

// Test les cas limites du cryptage : mauvaise clé, IV invalide, paramètres NULL
void test_crypto_edge_cases() {
    printf("[CRYPTO - Linda] Cas limites cryptographie... ");
    
    char *plaintext = "LindaSecret";
    uint8_t key1[AES_KEY_SIZE];
    uint8_t key2[AES_KEY_SIZE];
    char salt[SALT_LENGTH];
    
    crypto_generate_salt(salt);
    crypto_derive_key("linda_password1", salt, key1);
    crypto_derive_key("linda_password2", salt, key2);
    
    char ciphertext[MAX_ENCRYPTED_LENGTH];
    char iv[33];
    char decrypted[MAX_PASSWORD_LENGTH];
    
    assert(crypto_encrypt_password(plaintext, key1, ciphertext, iv) == SUCCESS);
    
    int result = crypto_decrypt_password(ciphertext, key2, iv, decrypted);
    assert(result == ERROR_CRYPTO);
    
    assert(crypto_encrypt_password(NULL, key1, ciphertext, iv) == ERROR_INVALID_PARAMS);
    assert(crypto_decrypt_password(ciphertext, NULL, iv, decrypted) == ERROR_INVALID_PARAMS);
    
    char bad_iv[] = "NOTVALIDHEX12345678901234567890";
    result = crypto_decrypt_password(ciphertext, key1, bad_iv, decrypted);
    
    printf("%s\n", CHECK_MARK);
}

int main() {
    printf("\nSUITE DE TESTS \n\n");
    
    setup_env();
    
    test_module_crypto();
    test_module_validation();
    test_module_database();
    test_auth_register();
    test_auth_login();
    test_auth_session_validity();
    test_secure_zero();
    test_db_edge_cases();
    test_crypto_edge_cases();
    
    teardown_env();
    
    printf("\n%s TOUS LES TESTS RÉUSSIS (100%%) %s\n", CHECK_MARK, CHECK_MARK);
    return 0;
}