#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "../common.h"
#include "../interface.h"
#include "../auth.h"
#include "../crypto.h" 

#define TEST_DB "test_integration.db"
#define CHECK_MARK "✓"

// Test le cycle complet : inscription, connexion, stockage et récupération de mot de passe
void test_scenario_complet() {
    printf("Scénario complet:\n");
    
    int res;
    Session session = {0};
    
    printf("  Inscription Inès... ");
    res = auth_register("Ines", "MotDePasseInes2024!");
    assert(res == SUCCESS);
    printf("%s\n", CHECK_MARK);
    
    printf("  Connexion... ");
    res = auth_login("Ines", "MotDePasseInes2024!", &session);
    assert(res == SUCCESS);
    assert(session.is_authenticated == 1);
    assert(session.user_id > 0);
    printf("%s\n", CHECK_MARK);
    
    printf("  Sauvegarde mot de passe... ");
    
    // Chiffre le service name
    char encrypted_service[MAX_ENCRYPTED_LENGTH], service_iv[33];
    crypto_encrypt_metadata("Instagram", session.master_key, encrypted_service, service_iv);
    
    // Chiffre le username
    char encrypted_username[MAX_ENCRYPTED_LENGTH], username_iv[33];
    crypto_encrypt_metadata("flavia.insta", session.master_key, encrypted_username, username_iv);
    
    // Chiffre le password
    char encrypted_password[MAX_ENCRYPTED_LENGTH], password_iv[33];
    crypto_encrypt_password("FlaviaPassword123", session.master_key, encrypted_password, password_iv);
    
    PasswordEntry entry;
    entry.user_id = session.user_id;
    strcpy(entry.service_name, encrypted_service);
    strcpy(entry.service_iv, service_iv);
    strcpy(entry.username, encrypted_username);
    strcpy(entry.username_iv, username_iv);
    strcpy(entry.encrypted_password, encrypted_password);
    strcpy(entry.iv, password_iv);
    
    int entry_id = db_store_password(&entry);
    assert(entry_id > 0);
    printf("%s\n", CHECK_MARK);
    
    printf("  Récupération et déchiffrement... ");
    PasswordEntry retrieved;
    res = db_get_password_entry(entry_id, session.user_id, &retrieved);
    assert(res == SUCCESS);
    
    char plaintext[MAX_PASSWORD_LENGTH];
    crypto_decrypt_password(retrieved.encrypted_password, session.master_key, retrieved.iv, plaintext);
    assert(strcmp(plaintext, "FlaviaPassword123") == 0);
    printf("%s\n", CHECK_MARK);
    
    auth_logout(&session);
    printf("\n");
}

// Test toutes les opérations CRUD (Create, Read, Update, Delete) sur les mots de passe
void test_scenario_crud_complet() {
    printf("Opérations CRUD:\n");
    
    Session session = {0};
    
    auth_register("Melissa", "MelissaSecure123!");
    auth_login("Melissa", "MelissaSecure123!", &session);
    
    printf("  Création de 3 entrées... ");
    
    // Entrée 1 : Gmail
    char encrypted_service1[MAX_ENCRYPTED_LENGTH], service_iv1[33];
    char encrypted_username1[MAX_ENCRYPTED_LENGTH], username_iv1[33];
    char encrypted_password1[MAX_ENCRYPTED_LENGTH], password_iv1[33];
    
    crypto_encrypt_metadata("Gmail", session.master_key, encrypted_service1, service_iv1);
    crypto_encrypt_metadata("ines@gmail.com", session.master_key, encrypted_username1, username_iv1);
    crypto_encrypt_password("InesGmail456", session.master_key, encrypted_password1, password_iv1);
    
    PasswordEntry entry1 = {0};
    entry1.user_id = session.user_id;
    strcpy(entry1.service_name, encrypted_service1);
    strcpy(entry1.service_iv, service_iv1);
    strcpy(entry1.username, encrypted_username1);
    strcpy(entry1.username_iv, username_iv1);
    strcpy(entry1.encrypted_password, encrypted_password1);
    strcpy(entry1.iv, password_iv1);
    
    // Entrée 2 : GitHub
    char encrypted_service2[MAX_ENCRYPTED_LENGTH], service_iv2[33];
    char encrypted_username2[MAX_ENCRYPTED_LENGTH], username_iv2[33];
    char encrypted_password2[MAX_ENCRYPTED_LENGTH], password_iv2[33];
    
    crypto_encrypt_metadata("GitHub", session.master_key, encrypted_service2, service_iv2);
    crypto_encrypt_metadata("jeremy_dev", session.master_key, encrypted_username2, username_iv2);
    crypto_encrypt_password("JeremyGitHub789", session.master_key, encrypted_password2, password_iv2);
    
    PasswordEntry entry2 = {0};
    entry2.user_id = session.user_id;
    strcpy(entry2.service_name, encrypted_service2);
    strcpy(entry2.service_iv, service_iv2);
    strcpy(entry2.username, encrypted_username2);
    strcpy(entry2.username_iv, username_iv2);
    strcpy(entry2.encrypted_password, encrypted_password2);
    strcpy(entry2.iv, password_iv2);
    
    // Entrée 3 : AWS
    char encrypted_service3[MAX_ENCRYPTED_LENGTH], service_iv3[33];
    char encrypted_username3[MAX_ENCRYPTED_LENGTH], username_iv3[33];
    char encrypted_password3[MAX_ENCRYPTED_LENGTH], password_iv3[33];
    
    crypto_encrypt_metadata("AWS", session.master_key, encrypted_service3, service_iv3);
    crypto_encrypt_metadata("linda_admin", session.master_key, encrypted_username3, username_iv3);
    crypto_encrypt_password("LindaAWS321", session.master_key, encrypted_password3, password_iv3);
    
    PasswordEntry entry3 = {0};
    entry3.user_id = session.user_id;
    strcpy(entry3.service_name, encrypted_service3);
    strcpy(entry3.service_iv, service_iv3);
    strcpy(entry3.username, encrypted_username3);
    strcpy(entry3.username_iv, username_iv3);
    strcpy(entry3.encrypted_password, encrypted_password3);
    strcpy(entry3.iv, password_iv3);
    
    int id1 = db_store_password(&entry1);
    int id2 = db_store_password(&entry2);
    int id3 = db_store_password(&entry3);
    
    assert(id1 > 0 && id2 > 0 && id3 > 0);
    printf("%s\n", CHECK_MARK);
    
    printf("  Lecture de toutes les entrées... ");
    PasswordEntry *all_entries = NULL;
    int count = 0;
    assert(db_get_user_passwords(session.user_id, &all_entries, &count) == SUCCESS);
    assert(count == 3);
    
    for (int i = 0; i < count; i++) {
        char plaintext[MAX_PASSWORD_LENGTH];
        int res = crypto_decrypt_password(
            all_entries[i].encrypted_password,
            session.master_key,
            all_entries[i].iv,
            plaintext
        );
        assert(res == SUCCESS);
        assert(strlen(plaintext) > 0);
    }
    free(all_entries);
    printf("%s\n", CHECK_MARK);
    
    printf("  Modification d'une entrée... ");
    PasswordEntry to_update;
    assert(db_get_password_entry(id2, session.user_id, &to_update) == SUCCESS);
    
    // Chiffre les nouvelles valeurs
    char new_encrypted_username[MAX_ENCRYPTED_LENGTH], new_username_iv[33];
    char new_encrypted_password[MAX_ENCRYPTED_LENGTH], new_password_iv[33];
    
    crypto_encrypt_metadata("flavia_coder", session.master_key, new_encrypted_username, new_username_iv);
    crypto_encrypt_password("FlaviaNewToken999", session.master_key, new_encrypted_password, new_password_iv);
    
    strcpy(to_update.username, new_encrypted_username);
    strcpy(to_update.username_iv, new_username_iv);
    strcpy(to_update.encrypted_password, new_encrypted_password);
    strcpy(to_update.iv, new_password_iv);
    
    assert(db_update_password(&to_update) == SUCCESS);
    
    PasswordEntry updated;
    assert(db_get_password_entry(id2, session.user_id, &updated) == SUCCESS);
    
    // Déchiffre pour vérifier
    char decrypted_username[MAX_USERNAME_LENGTH];
    char decrypted_password[MAX_PASSWORD_LENGTH];
    crypto_decrypt_metadata(updated.username, session.master_key, updated.username_iv, 
                           decrypted_username, sizeof(decrypted_username));
    crypto_decrypt_password(updated.encrypted_password, session.master_key, updated.iv, decrypted_password);
    
    assert(strcmp(decrypted_username, "flavia_coder") == 0);
    assert(strcmp(decrypted_password, "FlaviaNewToken999") == 0);
    printf("%s\n", CHECK_MARK);
    
    printf("  Suppression d'une entrée... ");
    assert(db_delete_password(id3, session.user_id) == SUCCESS);
    
    PasswordEntry deleted;
    assert(db_get_password_entry(id3, session.user_id, &deleted) != SUCCESS);
    
    PasswordEntry *remaining = NULL;
    int remaining_count = 0;
    assert(db_get_user_passwords(session.user_id, &remaining, &remaining_count) == SUCCESS);
    assert(remaining_count == 2);
    free(remaining);
    printf("%s\n", CHECK_MARK);
    
    auth_logout(&session);
    printf("\n");
}

// Test l'isolation des données entre différents utilisateurs (sécurité)
void test_scenario_isolation_users() {
    printf("Isolation entre utilisateurs:\n");
    
    auth_register("Alice", "AlicePassword2024!");
    auth_register("Bob", "BobSecure456!");
    
    Session ines_session = {0};
    Session melissa_session = {0};
    
    auth_login("Alice", "AlicePassword2024!", &ines_session);
    auth_login("Bob", "BobSecure456!", &melissa_session);
    
    printf("  Inès crée un secret... ");
    
    char encrypted_service[MAX_ENCRYPTED_LENGTH], service_iv[33];
    char encrypted_username[MAX_ENCRYPTED_LENGTH], username_iv[33];
    char encrypted_password[MAX_ENCRYPTED_LENGTH], password_iv[33];
    
    crypto_encrypt_metadata("InesService", ines_session.master_key, encrypted_service, service_iv);
    crypto_encrypt_metadata("ines_user", ines_session.master_key, encrypted_username, username_iv);
    crypto_encrypt_password("SecretInes2024", ines_session.master_key, encrypted_password, password_iv);
    
    PasswordEntry ines_entry = {0};
    ines_entry.user_id = ines_session.user_id;
    strcpy(ines_entry.service_name, encrypted_service);
    strcpy(ines_entry.service_iv, service_iv);
    strcpy(ines_entry.username, encrypted_username);
    strcpy(ines_entry.username_iv, username_iv);
    strcpy(ines_entry.encrypted_password, encrypted_password);
    strcpy(ines_entry.iv, password_iv);
    
    int ines_id = db_store_password(&ines_entry);
    assert(ines_id > 0);
    printf("%s\n", CHECK_MARK);
    
    printf("  Melissa tente d'accéder aux données d'Inès... ");
    PasswordEntry stolen;
    int result = db_get_password_entry(ines_id, melissa_session.user_id, &stolen);
    assert(result != SUCCESS); 
    printf("Bloqué %s\n", CHECK_MARK);
    
    printf("  Melissa tente de supprimer les données d'Inès... ");
    result = db_delete_password(ines_id, melissa_session.user_id);
    assert(result != SUCCESS); 
    printf("Bloqué %s\n", CHECK_MARK);
    
    printf("  Inès accède à ses propres données... ");
    PasswordEntry ines_retrieved;
    assert(db_get_password_entry(ines_id, ines_session.user_id, &ines_retrieved) == SUCCESS);
    
    char decrypted[MAX_PASSWORD_LENGTH];
    crypto_decrypt_password(ines_retrieved.encrypted_password, 
                          ines_session.master_key, 
                          ines_retrieved.iv, 
                          decrypted);
    assert(strcmp(decrypted, "SecretInes2024") == 0);
    printf("%s\n", CHECK_MARK);
    
    printf("  Melissa tente de déchiffrer avec sa clé... ");
    char melissa_attempt[MAX_PASSWORD_LENGTH];
    result = crypto_decrypt_password(ines_retrieved.encrypted_password,
                                    melissa_session.master_key,
                                    ines_retrieved.iv,
                                    melissa_attempt);
    assert(result == ERROR_CRYPTO); 
    printf("Échec attendu %s\n", CHECK_MARK);
    
    auth_logout(&ines_session);
    auth_logout(&melissa_session);
    printf("\n");
}

// Test la gestion des erreurs d'authentification (mauvais mdp, utilisateur inexistant, etc.)
void test_scenario_auth_errors() {
    printf("Gestion des erreurs d'authentification:\n");
    
    auth_register("Jeremy", "JeremySecure123!");
    
    printf("  Tentative avec mauvais mot de passe... ");
    Session bad_pass_session = {0};
    int res = auth_login("Jeremy", "MauvaisMotDePasse", &bad_pass_session);
    assert(res == ERROR_AUTH_FAILED);
    assert(bad_pass_session.is_authenticated == 0);
    printf("Rejeté %s\n", CHECK_MARK);
    
    printf("  Tentative avec utilisateur inexistant... ");
    Session no_user_session = {0};
    res = auth_login("Linda_Ghost", "Password123!", &no_user_session);
    assert(res == ERROR_AUTH_FAILED);
    printf("Rejeté %s\n", CHECK_MARK);
    
    printf("  Tentative de double inscription... ");
    res = auth_register("Jeremy", "AutrePassword456!");
    assert(res == ERROR_USER_EXISTS);
    printf("Bloqué %s\n", CHECK_MARK);
    
    printf("  Authentification valide et session active... ");
    Session valid_session = {0};
    res = auth_login("Jeremy", "JeremySecure123!", &valid_session);
    assert(res == SUCCESS);
    assert(auth_is_session_valid(&valid_session) == 1);
    printf("%s\n", CHECK_MARK);
    
    auth_logout(&valid_session);
    printf("\n");
}

// Test la persistence des données après fermeture et réouverture de la base de données
void test_scenario_persistence() {
    printf("Persistence des données:\n");
    
    printf("  Création et sauvegarde... ");
    auth_register("Linda", "LindaPersist2024!");
    Session session1 = {0};
    auth_login("Linda", "LindaPersist2024!", &session1);
    
    char encrypted_service[MAX_ENCRYPTED_LENGTH], service_iv[33];
    char encrypted_username[MAX_ENCRYPTED_LENGTH], username_iv[33];
    char encrypted_password[MAX_ENCRYPTED_LENGTH], password_iv[33];
    
    crypto_encrypt_metadata("LindaService", session1.master_key, encrypted_service, service_iv);
    crypto_encrypt_metadata("linda_persist", session1.master_key, encrypted_username, username_iv);
    crypto_encrypt_password("SecretPersistantLinda", session1.master_key, encrypted_password, password_iv);
    
    PasswordEntry entry = {0};
    entry.user_id = session1.user_id;
    strcpy(entry.service_name, encrypted_service);
    strcpy(entry.service_iv, service_iv);
    strcpy(entry.username, encrypted_username);
    strcpy(entry.username_iv, username_iv);
    strcpy(entry.encrypted_password, encrypted_password);
    strcpy(entry.iv, password_iv);
    
    int entry_id = db_store_password(&entry);
    assert(entry_id > 0);
    auth_logout(&session1);
    printf("%s\n", CHECK_MARK);
    
    printf("  Fermeture de la base de données... ");
    db_close();
    printf("%s\n", CHECK_MARK);
    
    printf("  Réouverture de la base de données... ");
    assert(db_init(TEST_DB) == SUCCESS);
    printf("%s\n", CHECK_MARK);

    printf("  Vérification des données persistées... ");
    Session session2 = {0};
    assert(auth_login("Linda", "LindaPersist2024!", &session2) == SUCCESS);
    
    PasswordEntry retrieved;
    assert(db_get_password_entry(entry_id, session2.user_id, &retrieved) == SUCCESS);
    
    char decrypted[MAX_PASSWORD_LENGTH];
    crypto_decrypt_password(retrieved.encrypted_password,
                          session2.master_key,
                          retrieved.iv,
                          decrypted);
    assert(strcmp(decrypted, "SecretPersistantLinda") == 0);
    printf("%s\n", CHECK_MARK);
    
    auth_logout(&session2);
    printf("\n");
}

int main() {
    printf("\n TESTS D'INTÉGRATION \n\n");
    
    unlink(TEST_DB);
    
    crypto_init();
    db_init(TEST_DB);
    auth_init();
    
    test_scenario_complet();
    test_scenario_crud_complet();
    test_scenario_isolation_users();
    test_scenario_auth_errors();
    test_scenario_persistence();
    
    auth_cleanup();
    db_close();
    crypto_cleanup();
    
    unlink(TEST_DB);
    
    printf("=== TOUS LES TESTS RÉUSSIS %s ===\n", CHECK_MARK);
    return 0;
}