# Quentry Recovery

[Français](#français) | [English](#english)

---

## Français

Récupérez facilement vos notes Quentry sécurisées après export ou désinstallation de l'application mobile.

### Téléchargement et installation

1. Cliquez sur le bouton vert **Code** en haut de cette page
2. Sélectionnez **Download ZIP**
3. Extrayez le fichier ZIP téléchargé
4. Double-cliquez sur **Quentry-Recovery-1.0.0.exe**

C'est tout ! Aucune installation requise.

### Utilisation

1. **Sélectionner le fichier backup** — Cliquez sur "Choisir un fichier" et sélectionnez votre fichier `.qb` exporté depuis l'app Quentry sur mobile

2. **Entrer votre PIN** — Saisissez le PIN que vous avez défini lors de la création du backup

3. **Visualiser vos notes** — Une fois déverrouillées, vos notes s'affichent avec leur formatage d'origine (gras, italique, listes, etc.)

4. **Copier ou exporter** — Utilisez les boutons pour :
   - Copier une note dans le presse-papiers
   - Exporter toutes les notes en JSON
   - Exporter toutes les notes en TXT

### Sécurité

- **100% hors-ligne** — Aucune donnée n'est envoyée sur Internet
- **PIN jamais stocké** — Votre PIN est utilisé uniquement pour le décryptage en mémoire
- **Chiffrement fort** — AES-256 + HMAC-SHA256 + PBKDF2 (600 000 itérations)

### FAQ

#### J'ai oublié mon PIN
Sans le PIN, impossible de récupérer vos notes. C'est une mesure de sécurité par conception.

#### Le décryptage prend du temps
C'est normal. Le processus utilise 600 000 itérations pour protéger vos données. La barre de progression indique l'avancement.

#### Windows me demande confirmation au lancement
Cliquez sur "Informations complémentaires" puis "Exécuter quand même". L'application n'est pas signée numériquement mais est 100% sûre.

---

## English

Easily recover your secure Quentry notes after exporting or uninstalling the mobile app.

### Download and Installation

1. Click the green **Code** button at the top of this page
2. Select **Download ZIP**
3. Extract the downloaded ZIP file
4. Double-click on **Quentry-Recovery-1.0.0.exe**

That's it! No installation required.

### Usage

1. **Select the backup file** — Click "Choose a file" and select your `.qb` file exported from the Quentry mobile app

2. **Enter your PIN** — Type the PIN you set when creating the backup

3. **View your notes** — Once unlocked, your notes are displayed with their original formatting (bold, italic, lists, etc.)

4. **Copy or export** — Use the buttons to:
   - Copy a note to clipboard
   - Export all notes as JSON
   - Export all notes as TXT

### Security

- **100% offline** — No data is sent over the Internet
- **PIN never stored** — Your PIN is only used for in-memory decryption
- **Strong encryption** — AES-256 + HMAC-SHA256 + PBKDF2 (600,000 iterations)

### FAQ

#### I forgot my PIN
Without the PIN, it's impossible to recover your notes. This is a security measure by design.

#### Decryption takes time
This is normal. The process uses 600,000 iterations to protect your data. The progress bar shows the advancement.

#### Windows asks for confirmation on launch
Click "More info" then "Run anyway". The application is not digitally signed but is 100% safe.

---

## License

MIT
