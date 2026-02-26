#ifndef INTERFACES_H
#define INTERFACES_H

#include "common.h"

int db_init(const char *db_path);
void db_close(void);
int db_create_user(const char *username, const char *password_hash, const char *salt);
int db_get_user_by_username(const char *username, User *user);
int db_get_user_by_id(int user_id, User *user);
int db_update_last_login(int user_id);
int db_store_password(const PasswordEntry *entry);
int db_get_user_passwords(int user_id, PasswordEntry **entries, int *count);
int db_get_password_entry(int entry_id, int user_id, PasswordEntry *entry);
int db_update_password(const PasswordEntry *entry);
int db_delete_password(int entry_id, int user_id);
int db_update_user_password(int user_id, const char *new_password_hash, const char *new_salt); // NOUVEAU

int crypto_init(void);
void crypto_cleanup(void);
int crypto_generate_salt(char *salt);
int crypto_hash_password(const char *password, const char *salt, char *hash);
int crypto_derive_key(const char *password, const char *salt, uint8_t *key);
int crypto_encrypt_password(const char *plaintext, const uint8_t *key,
                            char *ciphertext, char *iv);
int crypto_decrypt_password(const char *ciphertext, const uint8_t *key,
                            const char *iv, char *plaintext);

int auth_init(void);
void auth_cleanup(void);
int auth_register(const char *username, const char *password);
int auth_login(const char *username, const char *password, Session *session);
void auth_logout(Session *session);
int auth_is_session_valid(const Session *session);
int auth_change_master_password(Session *session, const char *old_password, const char *new_password); // NOUVEAU

#endif /* INTERFACES_H */