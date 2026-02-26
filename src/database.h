#ifndef DATABASE_H
#define DATABASE_H

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
int db_update_user_password(int user_id, const char *new_password_hash, const char *new_salt);

#endif /* DATABASE_H */