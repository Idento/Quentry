# Quentry Recovery

[Français](#français) | [English](#english)

## Français

Un petit programme Windows pour relire vos notes Quentry à partir d'une sauvegarde, par exemple après avoir changé de téléphone ou désinstallé l'application.

### Installation

Téléchargez le dépôt (bouton vert **Code**, puis **Download ZIP**), décompressez-le et lancez `Quentry-Recovery-1.0.0.exe`. Il n'y a rien à installer.

Au premier lancement, Windows affiche sans doute un avertissement. C'est parce que le programme n'est pas signé numériquement, un certificat de signature coûte cher pour un petit projet gratuit. Cliquez sur « Informations complémentaires » puis « Exécuter quand même ».

### Utilisation

1. Choisissez le fichier `.qb` que vous avez exporté depuis l'application Quentry.
2. Tapez le code PIN choisi au moment de la sauvegarde.
3. Vos notes s'affichent avec leur mise en forme (gras, italique, listes).
4. Vous pouvez copier une note, ou exporter toutes les notes en JSON ou en TXT.

### Sécurité

Le programme ne se connecte jamais à Internet, tout se passe sur votre ordinateur. Le PIN n'est gardé en mémoire que le temps de déchiffrer la sauvegarde, il n'est enregistré nulle part.

La sauvegarde est chiffrée en AES-256 avec un contrôle d'intégrité HMAC-SHA256, et la clé est dérivée du PIN par PBKDF2 avec 600 000 itérations. C'est ce qui rend le déchiffrement un peu lent, la barre de progression vous indique où il en est.

Si vous avez oublié votre PIN, les notes ne peuvent pas être récupérées, ni par vous ni par moi. C'est voulu.

## English

A small Windows program to read your Quentry notes from a backup, for example after switching phones or uninstalling the app.

### Installation

Download the repository (green **Code** button, then **Download ZIP**), unzip it and run `Quentry-Recovery-1.0.0.exe`. Nothing to install.

On first launch, Windows will probably show a warning. That's because the program isn't digitally signed, a code signing certificate is expensive for a small free project. Click "More info", then "Run anyway".

### How to use it

1. Pick the `.qb` file you exported from the Quentry app.
2. Type the PIN you chose when creating the backup.
3. Your notes appear with their formatting (bold, italic, lists).
4. You can copy a single note, or export all notes as JSON or TXT.

### Security

The program never connects to the Internet, everything happens on your computer. The PIN is only kept in memory while the backup is being decrypted, it is never saved anywhere.

The backup is encrypted with AES-256 with an HMAC-SHA256 integrity check, and the key is derived from your PIN with PBKDF2 at 600,000 iterations. That's why decryption takes a moment, the progress bar shows how far along it is.

If you forget your PIN, the notes cannot be recovered, not by you and not by me. That's on purpose.
