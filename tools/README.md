# Quentry Recovery Tool

**Script open-source pour récupérer vos notes Quentry après export/désinstallation**

## 🔒 Sécurité

Ce script utilise exactement le même algorithme de chiffrement que l'application Quentry v2.0+ :

- **Chiffrement** : AES-256-CTR (Advanced Encryption Standard)
- **Authentification** : HMAC-SHA256 (Encrypt-then-MAC)
- **Dérivation de clé** : PBKDF2-HMAC-SHA256 (310 000 itérations - OWASP 2023)
- **Salt** : 32 bytes aléatoires par backup
- **Nonce** : 12 bytes aléatoires par opération

**Votre PIN n'est jamais stocké ni transmis** - il est utilisé uniquement localement pour déchiffrer vos données.

## 📋 Prérequis

- Python 3.7 ou supérieur
- **pycryptodome** - `pip install pycryptodome`

## 🚀 Utilisation

```bash
# Installation des dépendances
pip install pycryptodome

# Récupération
python quentry_recovery.py mon_backup.qb
```

## 📁 Format de sortie

Le script génère automatiquement :
4. **Affichage terminal** - Lecture sans sauvegarde

### Structure des fichiers récupérés

```
quentry_recovered_backup/
├── backup_full.json          # Export complet JSON
└── entries/
    ├── 2026-01-15_prive_1.txt
    ├── 2026-01-16_pro_2.txt
    └── ...
```

## 🔐 Format du fichier .qb

Les fichiers de sauvegarde Quentry (.qb) sont structurés ainsi :

```
salt(hex):iv(hex):checksum(hex):encrypted(base64)
```

- **salt** : 16 bytes aléatoires (32 caractères hex)
- **iv** : 12 bytes aléatoires (24 caractères hex)
- **checksum** : SHA-256 des données en clair (64 caractères hex)
- **encrypted** : Données chiffrées en base64

## ❓ FAQ

### J'ai oublié mon PIN, puis-je récupérer mes notes ?

Non. Le PIN est la seule clé pour déchiffrer vos données. Sans lui, la récupération est impossible par conception (sécurité).

### Le script est-il sûr ?

Oui. Ce script :
- N'envoie aucune donnée sur Internet
- Ne stocke pas votre PIN
- Fonctionne 100% hors ligne
- Est open-source et vérifiable

### Puis-je utiliser ce script avec d'anciens backups ?

Ce script est compatible avec les backups Quentry v2.0. Les versions antérieures utilisaient un format différent.

## 📜 Licence

MIT License - Libre d'utilisation, modification et distribution.

## 🆘 Support

Si vous rencontrez des problèmes :
1. Vérifiez que votre fichier .qb n'est pas corrompu
2. Assurez-vous d'utiliser le bon PIN (celui utilisé lors de la création du backup)
3. Ouvrez une issue sur le dépôt GitHub

---

**Quentry** - Notes sécurisées
