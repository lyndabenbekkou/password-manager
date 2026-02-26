#include "auth.h"
#include "crypto.h"
#include "interface.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h> 
#include <termios.h>
#include <unistd.h>
#include <ctype.h>

// Vide le buffer d'entrée standard (stdin)
static void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

// Lit une ligne de manière sécurisée depuis stdin
static int read_line(char *buffer, size_t size) {
    if (!fgets(buffer, size, stdin)) {
        return 0;
    }
    
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    } else {
        clear_input_buffer();
    }
    
    return 1;
}

// Lit un mot de passe 
static int read_password(char *buffer, size_t size) {
    struct termios old_term, new_term;
    int show_password = 0;
    
    printf("Password (CTRL+V to show/hide): ");
    fflush(stdout);
    
    // Désactive l'écho
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    
    size_t i = 0;
    int c;
    
    while (i < size - 1) {
        c = getchar();
        
        if (c == '\n' || c == '\r' || c == EOF) {
            break;
        } 
        else if (c == 22) { // CTRL+V
            show_password = !show_password;
            
            printf("\r\033[K");
            if (show_password) {
                printf("Password (VISIBLE): %.*s", (int)i, buffer);
            } else {
                printf("Password (HIDDEN): ");
                for (size_t j = 0; j < i; j++) {
                    printf("*");
                }
            }
            fflush(stdout);
        }
        else if (c == 127 || c == 8) { // Backspace
            if (i > 0) {
                i--;
                printf("\b \b");
                fflush(stdout);
            }
        } 
        else if (isprint(c)) {
            buffer[i++] = c;
            
            if (show_password) {
                printf("%c", c);
            } else {
                printf("*");
            }
            fflush(stdout);
        }
    }
    
    buffer[i] = '\0';
    printf("\n");
    
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    
    return 1;
}

// Affiche le menu principal pour un utilisateur non connecté
static void display_main_menu(void) {
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║    PASSWORD MANAGER - MAIN MENU        ║\n");
    printf("╚════════════════════════════════════════╝\n");
    printf("\n");
    printf("  1. Register new account\n");
    printf("  2. Login\n");
    printf("  3. Exit\n");
    printf("\n");
    printf("Choose an option: ");
}

// Affiche le menu utilisateur pour un utilisateur connecté
static void display_user_menu(const Session *session) {
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║    LOGGED IN AS: %-21s ║\n", session->username);
    printf("╚════════════════════════════════════════╝\n");
    printf("\n");
    printf("  1. Add new password\n");
    printf("  2. List all passwords\n");
    printf("  3. Get a password\n");
    printf("  4. Delete a password\n");
    printf("  5. Change master password\n");
    printf("  6. Logout\n");
    printf("\n");
    printf("Choose an option: ");
}

// Gère l'inscription d'un nouvel utilisateur
static int handle_register(void) {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    
    printf("\n=== REGISTER NEW ACCOUNT ===\n\n");
    
    printf("Username (3-49 chars, alphanumeric + underscore): ");
    if (!read_line(username, sizeof(username))) {
        fprintf(stderr, "Error reading username\n");
        return ERROR_INVALID_PARAMS;
    }
    
    if (!read_password(password, sizeof(password))) {
        fprintf(stderr, "Error reading password\n");
        return ERROR_INVALID_PARAMS;
    }
    
    int result = auth_register(username, password);
    
    memset(password, 0, sizeof(password));
    
    if (result == SUCCESS) {
        printf("\n✅ %s\n", MSG_SUCCESS_REGISTER);
        return SUCCESS;
    } else {
        return result;
    }
}

// Gère la connexion d'un utilisateur existant
static int handle_login(Session *session) {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    
    printf("\n=== LOGIN ===\n\n");
    
    printf("Username: ");
    if (!read_line(username, sizeof(username))) {
        fprintf(stderr, "Error reading username\n");
        return ERROR_INVALID_PARAMS;
    }
    
    if (!read_password(password, sizeof(password))) {
        fprintf(stderr, "Error reading password\n");
        return ERROR_INVALID_PARAMS;
    }
    
    int result = auth_login(username, password, session);
    
    memset(password, 0, sizeof(password));
    
    if (result == SUCCESS) {
        printf("\n✅ %s\n", MSG_SUCCESS_LOGIN);
        return SUCCESS;
    } else {
        fprintf(stderr, "\n❌ %s\n", MSG_ERROR_AUTH_FAILED);
        return result;
    }
}

// Ajoute un mot de passe chiffré pour l'utilisateur courant
static void handle_add_password(Session *session) {
    char service_name[MAX_SERVICE_NAME_LENGTH];
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    
    printf("\n=== ADD PASSWORD ===\n\n");
    
    printf("Service name (e.g., Gmail, Facebook): ");
    if (!read_line(service_name, sizeof(service_name))) {
        fprintf(stderr, "Error reading service name\n");
        return;
    }
    
    if (strlen(service_name) == 0) {
        fprintf(stderr, "Error: Service name cannot be empty\n");
        return;
    }
    
    printf("Username for this service: ");
    if (!read_line(username, sizeof(username))) {
        fprintf(stderr, "Error reading username\n");
        return;
    }
    
    if (!read_password(password, sizeof(password))) {
        fprintf(stderr, "Error reading password\n");
        return;
    }
    
    if (strlen(password) == 0) {
        fprintf(stderr, "Error: Password cannot be empty\n");
        return;
    }
    
    // Chiffre le mot de passe
    char encrypted_password[MAX_ENCRYPTED_LENGTH];
    char password_iv[33];
    int result = crypto_encrypt_password(password, session->master_key, 
                                         encrypted_password, password_iv);
    memset(password, 0, sizeof(password));
    
    if (result != SUCCESS) {
        fprintf(stderr, "Error: Failed to encrypt password\n");
        return;
    }
    
    // Chiffre le service_name
    char encrypted_service[MAX_ENCRYPTED_LENGTH];
    char service_iv[33];
    result = crypto_encrypt_metadata(service_name, session->master_key,
                                     encrypted_service, service_iv);
    if (result != SUCCESS) {
        fprintf(stderr, "Error: Failed to encrypt service name\n");
        return;
    }
    
    // Chiffre le username
    char encrypted_username[MAX_ENCRYPTED_LENGTH];
    char username_iv[33];
    result = crypto_encrypt_metadata(username, session->master_key,
                                     encrypted_username, username_iv);
    if (result != SUCCESS) {
        fprintf(stderr, "Error: Failed to encrypt username\n");
        return;
    }
    
    // Crée l'entrée
    PasswordEntry entry;
    entry.user_id = session->user_id;
    
    strncpy(entry.service_name, encrypted_service, MAX_ENCRYPTED_LENGTH - 1);
    entry.service_name[MAX_ENCRYPTED_LENGTH - 1] = '\0';
    strncpy(entry.service_iv, service_iv, 32);
    entry.service_iv[32] = '\0';
    
    strncpy(entry.username, encrypted_username, MAX_ENCRYPTED_LENGTH - 1);
    entry.username[MAX_ENCRYPTED_LENGTH - 1] = '\0';
    strncpy(entry.username_iv, username_iv, 32);
    entry.username_iv[32] = '\0';
    
    strncpy(entry.encrypted_password, encrypted_password, MAX_ENCRYPTED_LENGTH - 1);
    entry.encrypted_password[MAX_ENCRYPTED_LENGTH - 1] = '\0';
    strncpy(entry.iv, password_iv, 32);
    entry.iv[32] = '\0';
    
    int entry_id = db_store_password(&entry);
    
    if (entry_id > 0) {
        printf("\n✅ %s\n", MSG_SUCCESS_PASSWORD_ADDED);
        printf("Password stored with ID: %d\n", entry_id);
    } else {
        fprintf(stderr, "\n❌ %s\n", MSG_ERROR_DB);
    }
}

// Liste tous les mots de passe stockés pour l'utilisateur courant
static void handle_list_passwords(Session *session) {
    printf("\n=== LIST PASSWORDS ===\n\n");
    
    PasswordEntry *entries = NULL;
    int count = 0;
    
    int result = db_get_user_passwords(session->user_id, &entries, &count);
    
    if (result != SUCCESS) {
        fprintf(stderr, "Error: Failed to retrieve passwords\n");
        return;
    }
    
    if (count == 0) {
        printf("No passwords stored yet.\n");
        printf("Use option 1 to add your first password.\n");
        return;
    }
    
    printf("You have %d password(s) stored:\n\n", count);
    printf("╔════╦═══════════════════════╦═══════════════════════╦═══════════════╗\n");
    printf("║ ID ║ Service               ║ Username              ║ Created       ║\n");
    printf("╠════╬═══════════════════════╬═══════════════════════╬═══════════════╣\n");
    
    for (int i = 0; i < count; i++) {
        // Déchiffre service_name
        char decrypted_service[MAX_SERVICE_NAME_LENGTH];
        if (crypto_decrypt_metadata(entries[i].service_name, 
                                   session->master_key,
                                   entries[i].service_iv,
                                   decrypted_service,
                                   sizeof(decrypted_service)) != SUCCESS) {
            strcpy(decrypted_service, "[Error]");
        }
        
        // Déchiffre username
        char decrypted_username[MAX_USERNAME_LENGTH];
        if (crypto_decrypt_metadata(entries[i].username,
                                   session->master_key,
                                   entries[i].username_iv,
                                   decrypted_username,
                                   sizeof(decrypted_username)) != SUCCESS) {
            strcpy(decrypted_username, "[Error]");
        }
        
        char date_str[20];
        struct tm *tm_info = localtime(&entries[i].created_at);
        strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M", tm_info);
        
        printf("║ %-2d ║ %-21s ║ %-21s ║ %-13s ║\n",
               entries[i].entry_id,
               decrypted_service,
               decrypted_username,
               date_str);
    }
    
    printf("╚════╩═══════════════════════╩═══════════════════════╩═══════════════╝\n");
    
    free(entries);
}

// Récupère et affiche un mot de passe déchiffré pour l'utilisateur courant
static void handle_get_password(Session *session) {
    printf("\n=== GET PASSWORD ===\n\n");
    
    printf("Enter password entry ID (use option 2 to see list): ");
    char id_str[10];
    if (!read_line(id_str, sizeof(id_str))) {
        fprintf(stderr, "Error reading ID\n");
        return;
    }
    
    int entry_id = atoi(id_str);
    if (entry_id <= 0) {
        fprintf(stderr, "Error: Invalid ID\n");
        return;
    }
    
    PasswordEntry entry;
    int result = db_get_password_entry(entry_id, session->user_id, &entry);
    
    if (result != SUCCESS) {
        fprintf(stderr, "Error: Password entry not found or access denied\n");
        return;
    }
    
    // Déchiffre service_name
    char decrypted_service[MAX_SERVICE_NAME_LENGTH];
    crypto_decrypt_metadata(entry.service_name, session->master_key,
                           entry.service_iv, decrypted_service,
                           sizeof(decrypted_service));
    
    // Déchiffre username
    char decrypted_username[MAX_USERNAME_LENGTH];
    crypto_decrypt_metadata(entry.username, session->master_key,
                           entry.username_iv, decrypted_username,
                           sizeof(decrypted_username));
    
    // Déchiffre password
    char decrypted_password[MAX_PASSWORD_LENGTH];
    result = crypto_decrypt_password(entry.encrypted_password, 
                                     session->master_key,
                                     entry.iv,
                                     decrypted_password);
    
    if (result != SUCCESS) {
        fprintf(stderr, "Error: Failed to decrypt password\n");
        return;
    }
    
    printf("\n┌───────────────────────────────────────┐\n");
    printf("│ PASSWORD DETAILS                      │\n");
    printf("├───────────────────────────────────────┤\n");
    printf("│ Service:  %-27s │\n", decrypted_service);
    printf("│ Username: %-27s │\n", decrypted_username);
    printf("│ Password: %-27s │\n", decrypted_password);
    printf("└───────────────────────────────────────┘\n");
    
    memset(decrypted_password, 0, sizeof(decrypted_password));
    memset(decrypted_service, 0, sizeof(decrypted_service));
    memset(decrypted_username, 0, sizeof(decrypted_username));
    
    printf("\n⚠️  Remember to clear your screen after copying the password!\n");
}

// Supprime une entrée de mot de passe après confirmation de l'utilisateur
static void handle_delete_password(Session *session) {
    printf("\n=== DELETE PASSWORD ===\n\n");
    
    printf("Enter password entry ID to delete (use option 2 to see list): ");
    char id_str[10];
    if (!read_line(id_str, sizeof(id_str))) {
        fprintf(stderr, "Error reading ID\n");
        return;
    }
    
    int entry_id = atoi(id_str);
    if (entry_id <= 0) {
        fprintf(stderr, "Error: Invalid ID\n");
        return;
    }
    
    PasswordEntry entry;
    int result = db_get_password_entry(entry_id, session->user_id, &entry);
    
    if (result != SUCCESS) {
        fprintf(stderr, "Error: Password entry not found or access denied\n");
        return;
    }
    
    // Déchiffre pour affichage
    char decrypted_service[MAX_SERVICE_NAME_LENGTH];
    char decrypted_username[MAX_USERNAME_LENGTH];
    
    crypto_decrypt_metadata(entry.service_name, session->master_key,
                           entry.service_iv, decrypted_service,
                           sizeof(decrypted_service));
    crypto_decrypt_metadata(entry.username, session->master_key,
                           entry.username_iv, decrypted_username,
                           sizeof(decrypted_username));
    
    printf("\nYou are about to delete:\n");
    printf("  Service:  %s\n", decrypted_service);
    printf("  Username: %s\n", decrypted_username);
    
    printf("\n⚠️  This action cannot be undone!\n");
    printf("Are you sure? (yes/no): ");
    char confirmation[10];
    if (!read_line(confirmation, sizeof(confirmation))) {
        fprintf(stderr, "Error reading confirmation\n");
        return;
    }
    
    if (strcasecmp(confirmation, "yes") != 0 && 
        strcasecmp(confirmation, "y") != 0) {
        printf("Deletion cancelled.\n");
        return;
    }
    
    result = db_delete_password(entry_id, session->user_id);
    
    if (result == SUCCESS) {
        printf("\n✅ %s\n", MSG_SUCCESS_PASSWORD_DELETED);
    } else {
        fprintf(stderr, "\n❌ Failed to delete password\n");
    }
}

// Change le mot de passe maître de l'utilisateur
static void handle_change_master_password(Session *session) {
    char old_password[MAX_PASSWORD_LENGTH];
    char new_password[MAX_PASSWORD_LENGTH];
    char confirm_password[MAX_PASSWORD_LENGTH];
    
    printf("\n=== CHANGE MASTER PASSWORD ===\n\n");
    
    printf("⚠️  This will re-encrypt ALL your stored passwords!\n");
    printf("⚠️  Make sure you remember your new password.\n\n");
    
    // Saisie de l'ancien mot de passe
    if (!read_password(old_password, sizeof(old_password))) {
        fprintf(stderr, "Error reading old password\n");
        return;
    }
    
    // Saisie du nouveau mot de passe
    printf("\nNew master ");
    if (!read_password(new_password, sizeof(new_password))) {
        fprintf(stderr, "Error reading new password\n");
        memset(old_password, 0, sizeof(old_password));
        return;
    }
    
    // Confirmation du nouveau mot de passe
    printf("\nConfirm new ");
    if (!read_password(confirm_password, sizeof(confirm_password))) {
        fprintf(stderr, "Error reading confirmation password\n");
        memset(old_password, 0, sizeof(old_password));
        memset(new_password, 0, sizeof(new_password));
        return;
    }
    
    // Vérification que les deux nouveaux mots de passe correspondent
    if (strcmp(new_password, confirm_password) != 0) {
        fprintf(stderr, "\n❌ Error: New passwords do not match\n");
        memset(old_password, 0, sizeof(old_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirm_password, 0, sizeof(confirm_password));
        return;
    }
    
    // Vérification que le nouveau est différent de l'ancien
    if (strcmp(old_password, new_password) == 0) {
        fprintf(stderr, "\n❌ Error: New password must be different from old password\n");
        memset(old_password, 0, sizeof(old_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirm_password, 0, sizeof(confirm_password));
        return;
    }
    
    printf("\n🔄 Changing master password...\n");
    printf("   This may take a few seconds...\n\n");
    
    // Appel de la fonction de changement
    int result = auth_change_master_password(session, old_password, new_password);
    
    // Nettoyage des mots de passe en mémoire
    memset(old_password, 0, sizeof(old_password));
    memset(new_password, 0, sizeof(new_password));
    memset(confirm_password, 0, sizeof(confirm_password));
    
    if (result == SUCCESS) {
        printf("✅ Master password changed successfully!\n");
        printf("   All your passwords have been re-encrypted.\n");
        printf("   Use your new password for next login.\n");
    } else {
        fprintf(stderr, "❌ Failed to change master password\n");
        
        // Messages d'erreur spécifiques
        switch (result) {
            case ERROR_AUTH_FAILED:
                fprintf(stderr, "   Reason: Old password is incorrect\n");
                break;
            case ERROR_INVALID_PARAMS:
                fprintf(stderr, "   Reason: New password does not meet requirements\n");
                break;
            case ERROR_CRYPTO:
                fprintf(stderr, "   Reason: Cryptographic operation failed\n");
                break;
            case ERROR_DB:
                fprintf(stderr, "   Reason: Database operation failed\n");
                break;
            default:
                fprintf(stderr, "   Reason: Unknown error\n");
        }
    }
}

// Gère la boucle du menu principal (non connecté)
static int main_menu_loop(Session *session) {
    int running = 1;
    
    while (running) {
        display_main_menu();
        
        char choice[10];
        if (!read_line(choice, sizeof(choice))) {
            continue;
        }
        
        switch (choice[0]) {
            case '1':
                handle_register();
                break;
                
            case '2':
                if (handle_login(session) == SUCCESS) {
                    return SUCCESS;
                }
                break;
                
            case '3':
                printf("\n%s\n", MSG_GOODBYE);
                running = 0;
                break;
                
            default:
                printf("\n❌ Invalid option. Please choose 1-3.\n");
                break;
        }
    }
    
    return ERROR_INVALID_PARAMS;
}

// Gère la boucle du menu utilisateur (connecté)
static int user_menu_loop(Session *session) {
    int running = 1;
    
    while (running) {
        if (!auth_is_session_valid(session)) {
            printf("\n⚠️  Session expired. Please login again.\n");
            auth_logout(session);
            return SUCCESS;
        }
        
        display_user_menu(session);
        
        char choice[10];
        if (!read_line(choice, sizeof(choice))) {
            continue;
        }
        
        switch (choice[0]) {
            case '1':
                handle_add_password(session);
                break;
                
            case '2':
                handle_list_passwords(session);
                break;
                
            case '3':
                handle_get_password(session);
                break;
                
            case '4':
                handle_delete_password(session);
                break;
                
            case '5':
                handle_change_master_password(session);
                break;
                
            case '6':
                printf("\n%s\n", MSG_SUCCESS_LOGOUT);
                auth_logout(session);
                running = 0;
                break;
                
            default:
                printf("\n❌ Invalid option. Please choose 1-6.\n");
                break;
        }
    }
    
    return SUCCESS;
}

// Point d'entrée principal de l'application de gestion de mots de passe
int main(void) {
    int result = SUCCESS;
    Session current_session = {0};
    
    printf("%s", MSG_WELCOME);
    printf("\nVersion: Beta (Work in Progress)\n");
    printf("Database integration: DONE\n");
    
    printf("\n🔧 Initializing modules...\n");
    
    if (crypto_init() != SUCCESS) {
        fprintf(stderr, "❌ Failed to initialize crypto module\n");
        return EXIT_FAILURE;
    }
    printf("   ✅ Crypto module initialized\n");
    
    if (db_init(DEFAULT_DB_PATH) != SUCCESS) {
        fprintf(stderr, "❌ Failed to initialize database\n");
        crypto_cleanup();
        return EXIT_FAILURE;
    }
    printf("   ✅ Database initialized\n");
    
    if (auth_init() != SUCCESS) {
        fprintf(stderr, "❌ Failed to initialize auth module\n");
        db_close();
        crypto_cleanup();
        return EXIT_FAILURE;
    }
    printf("   ✅ Auth module initialized\n");
    
    printf("\n✅ All modules initialized successfully!\n");
    
    int keep_running = 1;
    while (keep_running) {
        result = main_menu_loop(&current_session);
        
        if (result != SUCCESS) {
            break;
        }
        
        result = user_menu_loop(&current_session);
    }
    
    printf("\n🧹 Cleaning up...\n");
    auth_cleanup();
    db_close();
    crypto_cleanup();
    
    return EXIT_SUCCESS;
}