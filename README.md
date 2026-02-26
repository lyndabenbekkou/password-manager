# Password Manager — Gestionnaire de mots de passe chiffré

Gestionnaire de mots de passe local développé en C, avec chiffrement AES-256-CBC et dérivation de clé PBKDF2.

## Fonctionnalités

- Chiffrement AES-256-CBC des données stockées
- Dérivation de clé PBKDF2 avec 100 000 itérations
- Sel unique et IV aléatoire par chiffrement
- Protection contre les attaques par force brute
- Nettoyage mémoire sécurisé après utilisation
- Tests unitaires et tests d'intégration

## Structure du projet
```
src/
├── main.c          # Point d'entrée
├── auth.c/h        # Authentification
├── crypto.c/h      # Chiffrement AES-256-CBC / PBKDF2
├── database.c/h    # Gestion des données
├── interface.h     # Interface utilisateur
├── config.h        # Configuration
├── common.h        # Structures communes
├── Makefile        # Compilation
└── test/
    ├── test_unitaire.c
    └── test_integration.c
```

## Compilation
```bash
cd src
make
```

## Technologies

- Langage : C
- Chiffrement : OpenSSL (AES-256-CBC, PBKDF2)
- Build : Makefile
