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

## Support

Bei Fragen oder Problemen:
1. Erstelle ein Issue im GitHub Repository
2. Kontaktiere uns über Discord
3. Überprüfe die Logs im `mod-logs` Kanal

## Lizenz

Dieses Projekt steht unter der MIT-Lizenz.
