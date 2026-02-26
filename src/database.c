#include "database.h"
#include "config.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static sqlite3 *db = NULL;
static int db_initialized = 0;

// Convertit une chaîne datetime SQLite en timestamp UNIX
static time_t datetime_to_timestamp(const char *datetime) {
    if (!datetime) {
        return 0;
    }
    
    struct tm tm_info = {0};
    if (sscanf(datetime, "%d-%d-%d %d:%d:%d",
               &tm_info.tm_year, &tm_info.tm_mon, &tm_info.tm_mday,
               &tm_info.tm_hour, &tm_info.tm_min, &tm_info.tm_sec) != 6) {
        return 0;
    }
    
    tm_info.tm_year -= 1900;
    tm_info.tm_mon -= 1;
    
    return mktime(&tm_info);
}

// Initialise la base SQLite, crée les tables et l'index si nécessaire
int db_init(const char *db_path) {
    if (db_initialized) {
        DEBUG_PRINT("Database already initialized\n");
        return SUCCESS;
    }
    
    if (!db_path) {
        db_path = DEFAULT_DB_PATH;
    }
    
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        db = NULL;
        return ERROR_DB;
    }
    
    DEBUG_PRINT("Database opened: %s\n", db_path);
    
    char *err_msg = NULL;
    rc = sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to enable foreign keys: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        db = NULL;
        return ERROR_DB;
    }
    
    const char *create_users_table = 
        "CREATE TABLE IF NOT EXISTS users ("
        "    user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    username TEXT NOT NULL UNIQUE,"
        "    password_hash TEXT NOT NULL,"
        "    salt TEXT NOT NULL,"
        "    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "    last_login DATETIME"
        ");";
    
    rc = sqlite3_exec(db, create_users_table, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to create users table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        db = NULL;
        return ERROR_DB;
    }
    
    DEBUG_PRINT("Users table ready\n");
    
    const char *create_passwords_table = 
        "CREATE TABLE IF NOT EXISTS password_entries ("
        "    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    user_id INTEGER NOT NULL,"
        "    service_name TEXT NOT NULL,"
        "    service_iv TEXT NOT NULL,"
        "    username TEXT NOT NULL,"
        "    username_iv TEXT NOT NULL,"
        "    encrypted_password TEXT NOT NULL,"
        "    iv TEXT NOT NULL,"
        "    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "    modified_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE"
        ");";
    
    rc = sqlite3_exec(db, create_passwords_table, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to create password_entries table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        db = NULL;
        return ERROR_DB;
    }
    
    DEBUG_PRINT("Password entries table ready\n");
    
    const char *create_index = 
        "CREATE INDEX IF NOT EXISTS idx_passwords_user_id "
        "ON password_entries(user_id);";
    
    rc = sqlite3_exec(db, create_index, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Warning: Failed to create index: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    
    db_initialized = 1;
    DEBUG_PRINT("Database initialized successfully\n");
    return SUCCESS;
}

// Ferme la base SQLite et réinitialise l'état du module
void db_close(void) {
    if (!db_initialized || !db) {
        return;
    }
    
    sqlite3_close(db);
    db = NULL;
    db_initialized = 0;
    
    DEBUG_PRINT("Database closed\n");
}

// Crée un nouvel utilisateur et retourne son ID
int db_create_user(const char *username, const char *password_hash, const char *salt) {
    if (!db_initialized || !db) {
        fprintf(stderr, "Error: Database not initialized\n");
        return ERROR_DB;
    }
    
    if (!username || !password_hash || !salt) {
        fprintf(stderr, "Error: Invalid parameters (NULL)\n");
        return ERROR_INVALID_PARAMS;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = 
        "INSERT INTO users (username, password_hash, salt) "
        "VALUES (?, ?, ?);";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, salt, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        if (sqlite3_errcode(db) == SQLITE_CONSTRAINT) {
            fprintf(stderr, "Error: Username already exists\n");
            return ERROR_USER_EXISTS;
        }
        fprintf(stderr, "Error: Failed to insert user: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    int user_id = (int)sqlite3_last_insert_rowid(db);
    DEBUG_PRINT("User created with ID: %d\n", user_id);
    
    return user_id;
}

// Récupère un utilisateur à partir de son nom d'utilisateur
int db_get_user_by_username(const char *username, User *user) {
    if (!db_initialized || !db) {
        fprintf(stderr, "Error: Database not initialized\n");
        return ERROR_DB;
    }
    
    if (!username || !user) {
        fprintf(stderr, "Error: Invalid parameters (NULL)\n");
        return ERROR_INVALID_PARAMS;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = 
        "SELECT user_id, username, password_hash, salt, created_at, last_login "
        "FROM users WHERE username = ?;";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    
    if (rc == SQLITE_ROW) {
        user->user_id = sqlite3_column_int(stmt, 0);
        
        const char *db_username = (const char *)sqlite3_column_text(stmt, 1);
        strncpy(user->username, db_username, MAX_USERNAME_LENGTH - 1);
        user->username[MAX_USERNAME_LENGTH - 1] = '\0';
        
        const char *db_hash = (const char *)sqlite3_column_text(stmt, 2);
        strncpy(user->password_hash, db_hash, HASH_LENGTH - 1);
        user->password_hash[HASH_LENGTH - 1] = '\0';
        
        const char *db_salt = (const char *)sqlite3_column_text(stmt, 3);
        strncpy(user->salt, db_salt, SALT_LENGTH - 1);
        user->salt[SALT_LENGTH - 1] = '\0';
        
        const char *created_at_str = (const char *)sqlite3_column_text(stmt, 4);
        user->created_at = datetime_to_timestamp(created_at_str);
        
        const char *last_login_str = (const char *)sqlite3_column_text(stmt, 5);
        user->last_login = last_login_str ? datetime_to_timestamp(last_login_str) : 0;
        
        sqlite3_finalize(stmt);
        DEBUG_PRINT("User found: %s (ID: %d)\n", user->username, user->user_id);
        return SUCCESS;
    }
    
    sqlite3_finalize(stmt);
    
    if (rc == SQLITE_DONE) {
        DEBUG_PRINT("User not found: %s\n", username);
        return ERROR_USER_NOT_FOUND;
    }
    
    fprintf(stderr, "Error: Database query failed: %s\n", sqlite3_errmsg(db));
    return ERROR_DB;
}

// Récupère un utilisateur à partir de son identifiant
int db_get_user_by_id(int user_id, User *user) {
    if (!db_initialized || !db) {
        fprintf(stderr, "Error: Database not initialized\n");
        return ERROR_DB;
    }
    
    if (user_id <= 0 || !user) {
        fprintf(stderr, "Error: Invalid parameters\n");
        return ERROR_INVALID_PARAMS;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = 
        "SELECT user_id, username, password_hash, salt, created_at, last_login "
        "FROM users WHERE user_id = ?;";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    
    rc = sqlite3_step(stmt);
    
    if (rc == SQLITE_ROW) {
        user->user_id = sqlite3_column_int(stmt, 0);
        
        const char *db_username = (const char *)sqlite3_column_text(stmt, 1);
        strncpy(user->username, db_username, MAX_USERNAME_LENGTH - 1);
        user->username[MAX_USERNAME_LENGTH - 1] = '\0';
        
        const char *db_hash = (const char *)sqlite3_column_text(stmt, 2);
        strncpy(user->password_hash, db_hash, HASH_LENGTH - 1);
        user->password_hash[HASH_LENGTH - 1] = '\0';
        
        const char *db_salt = (const char *)sqlite3_column_text(stmt, 3);
        strncpy(user->salt, db_salt, SALT_LENGTH - 1);
        user->salt[SALT_LENGTH - 1] = '\0';
        
        const char *created_at_str = (const char *)sqlite3_column_text(stmt, 4);
        user->created_at = datetime_to_timestamp(created_at_str);
        
        const char *last_login_str = (const char *)sqlite3_column_text(stmt, 5);
        user->last_login = last_login_str ? datetime_to_timestamp(last_login_str) : 0;
        
        sqlite3_finalize(stmt);
        DEBUG_PRINT("User found: %s (ID: %d)\n", user->username, user->user_id);
        return SUCCESS;
    }
    
    sqlite3_finalize(stmt);
    
    if (rc == SQLITE_DONE) {
        DEBUG_PRINT("User not found with ID: %d\n", user_id);
        return ERROR_USER_NOT_FOUND;
    }
    
    fprintf(stderr, "Error: Database query failed: %s\n", sqlite3_errmsg(db));
    return ERROR_DB;
}

// Met à jour la date de dernière connexion d'un utilisateur
int db_update_last_login(int user_id) {
    if (!db_initialized || !db) {
        fprintf(stderr, "Error: Database not initialized\n");
        return ERROR_DB;
    }
    
    if (user_id <= 0) {
        fprintf(stderr, "Error: Invalid user_id\n");
        return ERROR_INVALID_PARAMS;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?;";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error: Failed to update last_login: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    DEBUG_PRINT("Updated last_login for user %d\n", user_id);
    return SUCCESS;
}

// Enregistre une nouvelle entrée de mot de passe pour un utilisateur
int db_store_password(const PasswordEntry *entry) {
    if (!db_initialized || !db) {
        fprintf(stderr, "Error: Database not initialized\n");
        return ERROR_DB;
    }
    
    if (!entry) {
        fprintf(stderr, "Error: Invalid parameter (NULL)\n");
        return ERROR_INVALID_PARAMS;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = 
        "INSERT INTO password_entries "
        "(user_id, service_name, service_iv, username, username_iv, encrypted_password, iv) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    sqlite3_bind_int(stmt, 1, entry->user_id);
    sqlite3_bind_text(stmt, 2, entry->service_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry->service_iv, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->username_iv, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, entry->encrypted_password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, entry->iv, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error: Failed to insert password entry: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    int entry_id = (int)sqlite3_last_insert_rowid(db);
    DEBUG_PRINT("Password entry created with ID: %d\n", entry_id);
    
    return entry_id;
}

// Récupère toutes les entrées de mot de passe d'un utilisateur
int db_get_user_passwords(int user_id, PasswordEntry **entries, int *count) {
    if (!db_initialized || !db) {
        fprintf(stderr, "Error: Database not initialized\n");
        return ERROR_DB;
    }
    
    if (user_id <= 0 || !entries || !count) {
        fprintf(stderr, "Error: Invalid parameters\n");
        return ERROR_INVALID_PARAMS;
    }
    
    *entries = NULL;
    *count = 0;
    
    sqlite3_stmt *count_stmt;
    const char *count_sql = "SELECT COUNT(*) FROM password_entries WHERE user_id = ?;";
    
    int rc = sqlite3_prepare_v2(db, count_sql, -1, &count_stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare count statement: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    sqlite3_bind_int(count_stmt, 1, user_id);
    
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        *count = sqlite3_column_int(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);
    
    if (*count == 0) {
        DEBUG_PRINT("No password entries found for user %d\n", user_id);
        return SUCCESS;
    }
    
    *entries = (PasswordEntry *)malloc(sizeof(PasswordEntry) * (*count));
    if (!*entries) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        *count = 0;
        return ERROR_MEMORY;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = 
        "SELECT entry_id, user_id, service_name, service_iv, username, username_iv, "
        "encrypted_password, iv, created_at, modified_at "
        "FROM password_entries WHERE user_id = ? ORDER BY created_at DESC;";
    
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        free(*entries);
        *entries = NULL;
        *count = 0;
        return ERROR_DB;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    
    int index = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && index < *count) {
        PasswordEntry *entry = &(*entries)[index];
        
        entry->entry_id = sqlite3_column_int(stmt, 0);
        entry->user_id = sqlite3_column_int(stmt, 1);
        
        const char *service = (const char *)sqlite3_column_text(stmt, 2);
        strncpy(entry->service_name, service, MAX_ENCRYPTED_LENGTH - 1);
        entry->service_name[MAX_ENCRYPTED_LENGTH - 1] = '\0';
        
        const char *service_iv = (const char *)sqlite3_column_text(stmt, 3);
        strncpy(entry->service_iv, service_iv, 32);
        entry->service_iv[32] = '\0';
        
        const char *username = (const char *)sqlite3_column_text(stmt, 4);
        strncpy(entry->username, username, MAX_ENCRYPTED_LENGTH - 1);
        entry->username[MAX_ENCRYPTED_LENGTH - 1] = '\0';
        
        const char *username_iv = (const char *)sqlite3_column_text(stmt, 5);
        strncpy(entry->username_iv, username_iv, 32);
        entry->username_iv[32] = '\0';
        
        const char *encrypted = (const char *)sqlite3_column_text(stmt, 6);
        strncpy(entry->encrypted_password, encrypted, MAX_ENCRYPTED_LENGTH - 1);
        entry->encrypted_password[MAX_ENCRYPTED_LENGTH - 1] = '\0';
        
        const char *iv = (const char *)sqlite3_column_text(stmt, 7);
        strncpy(entry->iv, iv, 32);
        entry->iv[32] = '\0';
        
        const char *created_at_str = (const char *)sqlite3_column_text(stmt, 8);
        entry->created_at = datetime_to_timestamp(created_at_str);
        
        const char *modified_at_str = (const char *)sqlite3_column_text(stmt, 9);
        entry->modified_at = datetime_to_timestamp(modified_at_str);
        
        index++;
    }
    
    sqlite3_finalize(stmt);
    
    DEBUG_PRINT("Retrieved %d password entries for user %d\n", *count, user_id);
    return SUCCESS;
}

// Récupère une entrée de mot de passe précise pour un utilisateur
int db_get_password_entry(int entry_id, int user_id, PasswordEntry *entry) {
    if (!db_initialized || !db) {
        fprintf(stderr, "Error: Database not initialized\n");
        return ERROR_DB;
    }
    
    if (entry_id <= 0 || user_id <= 0 || !entry) {
        fprintf(stderr, "Error: Invalid parameters\n");
        return ERROR_INVALID_PARAMS;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = 
        "SELECT entry_id, user_id, service_name, service_iv, username, username_iv, "
        "encrypted_password, iv, created_at, modified_at "
        "FROM password_entries WHERE entry_id = ? AND user_id = ?;";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    sqlite3_bind_int(stmt, 1, entry_id);
    sqlite3_bind_int(stmt, 2, user_id);
    
    rc = sqlite3_step(stmt);
    
    if (rc == SQLITE_ROW) {
        entry->entry_id = sqlite3_column_int(stmt, 0);
        entry->user_id = sqlite3_column_int(stmt, 1);
        
        const char *service = (const char *)sqlite3_column_text(stmt, 2);
        strncpy(entry->service_name, service, MAX_ENCRYPTED_LENGTH - 1);
        entry->service_name[MAX_ENCRYPTED_LENGTH - 1] = '\0';
        
        const char *service_iv = (const char *)sqlite3_column_text(stmt, 3);
        strncpy(entry->service_iv, service_iv, 32);
        entry->service_iv[32] = '\0';
        
        const char *username = (const char *)sqlite3_column_text(stmt, 4);
        strncpy(entry->username, username, MAX_ENCRYPTED_LENGTH - 1);
        entry->username[MAX_ENCRYPTED_LENGTH - 1] = '\0';
        
        const char *username_iv = (const char *)sqlite3_column_text(stmt, 5);
        strncpy(entry->username_iv, username_iv, 32);
        entry->username_iv[32] = '\0';
        
        const char *encrypted = (const char *)sqlite3_column_text(stmt, 6);
        strncpy(entry->encrypted_password, encrypted, MAX_ENCRYPTED_LENGTH - 1);
        entry->encrypted_password[MAX_ENCRYPTED_LENGTH - 1] = '\0';
        
        const char *iv = (const char *)sqlite3_column_text(stmt, 7);
        strncpy(entry->iv, iv, 32);
        entry->iv[32] = '\0';
        
        const char *created_at_str = (const char *)sqlite3_column_text(stmt, 8);
        entry->created_at = datetime_to_timestamp(created_at_str);
        
        const char *modified_at_str = (const char *)sqlite3_column_text(stmt, 9);
        entry->modified_at = datetime_to_timestamp(modified_at_str);
        
        sqlite3_finalize(stmt);
        DEBUG_PRINT("Password entry found: ID %d\n", entry_id);
        return SUCCESS;
    }
    
    sqlite3_finalize(stmt);
    
    if (rc == SQLITE_DONE) {
        DEBUG_PRINT("Password entry not found: ID %d\n", entry_id);
        return ERROR_DB;
    }
    
    fprintf(stderr, "Error: Database query failed: %s\n", sqlite3_errmsg(db));
    return ERROR_DB;
}

// Met à jour une entrée de mot de passe existante
int db_update_password(const PasswordEntry *entry) {
    if (!db_initialized || !db) {
        fprintf(stderr, "Error: Database not initialized\n");
        return ERROR_DB;
    }
    
    if (!entry || entry->entry_id <= 0) {
        fprintf(stderr, "Error: Invalid parameters\n");
        return ERROR_INVALID_PARAMS;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = 
        "UPDATE password_entries SET "
        "service_name = ?, service_iv = ?, username = ?, username_iv = ?, "
        "encrypted_password = ?, iv = ?, modified_at = CURRENT_TIMESTAMP "
        "WHERE entry_id = ? AND user_id = ?;";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    sqlite3_bind_text(stmt, 1, entry->service_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry->service_iv, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->username_iv, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->encrypted_password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, entry->iv, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, entry->entry_id);
    sqlite3_bind_int(stmt, 8, entry->user_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error: Failed to update password entry: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    if (sqlite3_changes(db) == 0) {
        fprintf(stderr, "Error: No password entry found to update\n");
        return ERROR_DB;
    }
    
    DEBUG_PRINT("Password entry updated: ID %d\n", entry->entry_id);
    return SUCCESS;
}

// Supprime une entrée de mot de passe pour un utilisateur
int db_delete_password(int entry_id, int user_id) {
    if (!db_initialized || !db) {
        fprintf(stderr, "Error: Database not initialized\n");
        return ERROR_DB;
    }
    
    if (entry_id <= 0 || user_id <= 0) {
        fprintf(stderr, "Error: Invalid parameters\n");
        return ERROR_INVALID_PARAMS;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM password_entries WHERE entry_id = ? AND user_id = ?;";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    sqlite3_bind_int(stmt, 1, entry_id);
    sqlite3_bind_int(stmt, 2, user_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error: Failed to delete password entry: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    if (sqlite3_changes(db) == 0) {
        fprintf(stderr, "Error: No password entry found to delete\n");
        return ERROR_DB;
    }
    
    DEBUG_PRINT("Password entry deleted: ID %d\n", entry_id);
    return SUCCESS;
}

// Met à jour le mot de passe maître (hash et sel) d'un utilisateur
int db_update_user_password(int user_id, const char *new_password_hash, const char *new_salt) {
    if (!db_initialized || !db) {
        fprintf(stderr, "Error: Database not initialized\n");
        return ERROR_DB;
    }
    
    if (user_id <= 0 || !new_password_hash || !new_salt) {
        fprintf(stderr, "Error: Invalid parameters\n");
        return ERROR_INVALID_PARAMS;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = "UPDATE users SET password_hash = ?, salt = ? WHERE user_id = ?;";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    sqlite3_bind_text(stmt, 1, new_password_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, new_salt, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, user_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error: Failed to update password: %s\n", sqlite3_errmsg(db));
        return ERROR_DB;
    }
    
    if (sqlite3_changes(db) == 0) {
        fprintf(stderr, "Error: User not found\n");
        return ERROR_USER_NOT_FOUND;
    }
    
    DEBUG_PRINT("Password updated for user %d\n", user_id);
    return SUCCESS;
}