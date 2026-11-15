# Quentry Recovery

[Français](#français) | [English](#english)

## Français

Un petit programme Windows, et un script pour tous les ordinateurs, pour relire vos notes Quentry à partir d'une sauvegarde, par exemple après avoir changé de téléphone ou désinstallé l'application.

### Sans le programme Windows, en 3 lignes (Windows, Mac ou Linux, avec Python 3)

```
pip install pycryptodome
python tools/quentry_recovery.py ma-sauvegarde.qb
```

Tapez ensuite le PIN choisi au moment de la sauvegarde : vos notes arrivent dans un dossier `recovered_...`, une note par fichier texte. Le script est ici : [tools/quentry_recovery.py](tools/quentry_recovery.py). Il est court et se lit facilement.

### Installation du programme Windows

Téléchargez `Quentry-Recovery-1.2.0.exe` sur la page [Releases](https://github.com/Idento/Quentry/releases/latest) et lancez-le. Il n'y a rien à installer.

Pour vérifier que le fichier est bien celui publié ici, tapez `certutil -hashfile Quentry-Recovery-1.2.0.exe SHA256` dans un terminal : l'empreinte doit être celle écrite sous la version.

Au premier lancement, Windows affiche sans doute un avertissement. C'est parce que le programme n'est pas signé numériquement, un certificat de signature coûte cher pour un petit projet gratuit. Cliquez sur « Informations complémentaires » puis « Exécuter quand même ».

### Utilisation

1. Choisissez le fichier `.qb` que vous avez exporté depuis l'application Quentry.
2. Tapez le code PIN choisi au moment de la sauvegarde.
3. Vos notes s'affichent avec leur mise en forme (gras, italique, listes).
4. Vous pouvez copier une note, ou exporter toutes les notes en JSON ou en TXT.

Tous les fichiers `.qb` se relisent, même les plus anciens. Les sauvegardes récentes contiennent aussi vos modèles de notes et votre corbeille (les notes supprimées depuis moins de 30 jours, à partir de Quentry 2.1.0) : ils sont exportés à part, à côté de vos notes.

### Sécurité

Le programme et le script ne se connectent jamais à Internet, tout se passe sur votre ordinateur. Le PIN n'est gardé en mémoire que le temps de déchiffrer la sauvegarde, il n'est enregistré nulle part.

La sauvegarde est chiffrée en AES-256 avec un contrôle d'intégrité HMAC-SHA256, et la clé est dérivée du PIN par PBKDF2 avec 600 000 itérations. C'est ce qui rend le déchiffrement un peu lent, la barre de progression vous indique où il en est.

Si vous avez oublié votre PIN, les notes ne peuvent pas être récupérées, ni par vous ni par moi. C'est voulu.

## English

A small Windows program, and a script for any computer, to read your Quentry notes from a backup, for example after switching phones or uninstalling the app.

### Without the Windows program, in 3 lines (Windows, Mac or Linux, with Python 3)

```
pip install pycryptodome
python tools/quentry_recovery.py my-backup.qb
```

Then type the PIN you chose when creating the backup: your notes land in a `recovered_...` folder, one text file per note. The script is here: [tools/quentry_recovery.py](tools/quentry_recovery.py). It is short and easy to read.

### Installing the Windows program

Download `Quentry-Recovery-1.2.0.exe` from the [Releases](https://github.com/Idento/Quentry/releases/latest) page and run it. Nothing to install.

To check that the file is the one published here, type `certutil -hashfile Quentry-Recovery-1.2.0.exe SHA256` in a terminal: the fingerprint must match the one written under the release.

On first launch, Windows will probably show a warning. That's because the program isn't digitally signed, a code signing certificate is expensive for a small free project. Click "More info", then "Run anyway".

### How to use it

1. Pick the `.qb` file you exported from the Quentry app.
2. Type the PIN you chose when creating the backup.
3. Your notes appear with their formatting (bold, italic, lists).
4. You can copy a single note, or export all notes as JSON or TXT.

Every `.qb` file can be read, even the oldest ones. Recent backups also hold your note templates and your trash (notes deleted less than 30 days ago, from Quentry 2.1.0 on): they are exported separately, next to your notes.

### Security

The program and the script never connect to the Internet, everything happens on your computer. The PIN is only kept in memory while the backup is being decrypted, it is never saved anywhere.

The backup is encrypted with AES-256 with an HMAC-SHA256 integrity check, and the key is derived from your PIN with PBKDF2 at 600,000 iterations. That's why decryption takes a moment, the progress bar shows how far along it is.

If you forget your PIN, the notes cannot be recovered, not by you and not by me. That's on purpose.

## License

[MIT](LICENSE)
