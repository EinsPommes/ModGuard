# ModGuard - KI-gesteuerter Discord Moderations-Bot

ModGuard ist ein intelligenter Discord-Bot, der mithilfe von künstlicher Intelligenz die Kommunikation auf deinem Server überwacht und moderiert.

## Hauptfunktionen

- **KI-gestützte Nachrichtenanalyse**
  - Automatische Erkennung von Beleidigungen und anstößigen Inhalten
  - Kontextbezogene Analyse durch GPT-4
  - Mehrsprachige Moderation (Deutsch & Englisch)

- **Automatische Moderation**
  - Konfigurierbare Warnstufen (mild, moderat, schwer)
  - Automatische Aktionen (Warnung, Timeout, Bann)
  - Whitelist für erlaubte Ausdrücke

- **Moderations-Dashboard**
  - Übersichtliche Web-Oberfläche
  - Echtzeit-Statistiken
  - Verwaltung der Moderationseinstellungen

## Voraussetzungen

- Python 3.8 oder höher
- Discord Bot Token
- OpenAI API Key

## Installation

1. Repository klonen:
   ```bash
   git clone https://github.com/dein-username/ModGuard.git
   cd ModGuard
   ```

2. Abhängigkeiten installieren:
   ```bash
   pip install -r requirements.txt
   ```

3. Umgebungsvariablen einrichten:
   - Erstelle eine `.env` Datei im Hauptverzeichnis
   - Füge folgende Variablen hinzu:
     ```
     DISCORD_TOKEN=dein_discord_token
     OPENAI_API_KEY=dein_openai_api_key
     ```

## Start des Bots

1. Bot starten:
   ```bash
   python bot.py
   ```

2. Web-Interface starten:
   ```bash
   python web_ui.py
   ```

## Konfiguration

Die Konfiguration kann über die Web-Oberfläche oder direkt in der `config.json` vorgenommen werden:

```json
{
    "warning_levels": {
        "mild": {
            "action": "warn",
            "threshold": 0.7
        },
        "moderate": {
            "action": "timeout",
            "threshold": 0.8
        },
        "severe": {
            "action": "ban",
            "threshold": 0.9
        }
    },
    "timeout_duration": 3600,
    "log_channel_name": "mod-logs",
    "whitelist": [],
    "language": "de"
}
```

## Moderationsaktionen

- **Warnung**: Der Nutzer erhält eine private Nachricht
- **Timeout**: Temporärer Ausschluss von der Kommunikation
- **Bann**: Permanenter Ausschluss vom Server

## Web-Interface

Das Web-Interface ist erreichbar unter:
- URL: `http://localhost:8000`
- Funktionen:
  - Übersicht aller Moderationsaktionen
  - Konfiguration der Warnstufen
  - Verwaltung der Whitelist

## 🔒 Enhanced URL Safety Features

### URL Safety Detection
- Advanced URL pattern recognition
- Detection of known malware test files (EICAR, etc.)
- Integration with urlscan.io for real-time URL scanning
- Automatic unsafe URL deletion
- User warning system with customizable messages

### Security Measures
- Pattern-based malware detection
- Real-time URL scanning
- Comprehensive error handling
- Detailed security logging
- Automatic message deletion for unsafe content

### Recent Updates
- Improved URL pattern recognition
- Added detection for known malware test files
- Enhanced error handling and logging
- Better warning message system
- More detailed scan results

## 🔑 Required Permissions

The bot requires the following Discord permissions to function properly:

### Essential Permissions
- `Moderate Members` - Required for timeout functionality
- `Kick Members` - Required for kick functionality
- `Ban Members` - Required for ban functionality
- `Manage Messages` - Required to delete unsafe messages

### Other Permissions
- `Send Messages` - To send warning messages
- `Read Message History` - To process messages
- `View Channels` - To monitor channels

### Setting Up Permissions
1. Go to your Discord Server Settings
2. Click on "Roles"
3. Create a new role for ModGuard or edit its existing role
4. Enable the required permissions listed above
5. Make sure the bot's role is higher in the hierarchy than the roles it needs to moderate

### Bot Invite Link
When inviting the bot, make sure to select all the required permissions. You can use this invite link template (replace CLIENT_ID with your bot's client ID):
```
https://discord.com/api/oauth2/authorize?client_id=CLIENT_ID&permissions=1099780138048&scope=bot
```

This link includes all necessary permissions for full functionality.

## 🛡️ Moderation Commands

### User Management
- `!kick @user [reason]` - Kick a user from the server
- `!ban @user [reason]` - Ban a user from the server
- `!timeout @user <duration> [unit] [reason]` - Timeout a user
  - Units: s (seconds), m (minutes), h (hours), d (days)
  - Example: `!timeout @user 10 m Spamming`
- `!untimeout @user` - Remove timeout from a user

### Required Permissions
- Kick command requires "Kick Members" permission
- Ban command requires "Ban Members" permission
- Timeout commands require "Moderate Members" permission

## Support

Bei Fragen oder Problemen:
1. Erstelle ein Issue im GitHub Repository
2. Kontaktiere uns über Discord
3. Überprüfe die Logs im `mod-logs` Kanal

## Lizenz

Dieses Projekt steht unter der MIT-Lizenz.
