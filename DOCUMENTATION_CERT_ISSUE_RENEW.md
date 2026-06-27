# Dokumentation: Zertifikats-Management in FreePBX (Issue vs. Renew)

Diese Dokumentation beschreibt, wie das FreePBX-Modul `certman` (Certificate Manager) zwischen der Erstausstellung (Issue) und der Erneuerung (Renew) eines Zertifikats unterscheidet und an welchen Stellen im Code diese Prozesse ausgeführt werden.

## 1. Unterscheidung zwischen Issue und Renew (Let's Encrypt)

Die Unterscheidung erfolgt primär in der Funktion `updateLE` innerhalb der Klasse `Certman`. Dabei wird geprüft, ob bereits ein Zertifikat für den angegebenen Host existiert und wie lange dieses noch gültig ist.

### Logik-Check
In `Certman.class.php` (ca. Zeile 824) wird die Entscheidung getroffen:

1.  **Issue (Erstausstellung):** Wenn die Zertifikatsdatei (`cert.pem`) im entsprechenden Host-Verzeichnis noch nicht existiert, wird `$needsgen` auf `true` gesetzt.
2.  **Renew (Erneuerung):** Wenn die Datei existiert, wird das Ablaufdatum geprüft.
    *   Es wird ein Schwellenwert (`$renewafter`) berechnet: `Ablaufdatum - Alarmtage` (Standardmäßig meist 30 Tage).
    *   Ist die aktuelle Zeit größer als `$renewafter` ODER ist der Parameter `$force` auf `true` gesetzt, wird `$needsgen` ebenfalls auf `true` gesetzt.

```php
// Certman.class.php: Zeile 824ff
if (!file_exists($certfile)) {
    // Kein Zertifikat vorhanden -> Neuanforderung (Issue)
    $needsgen = true;
} else {
    // Zertifikat existiert bereits
    $certdata = openssl_x509_parse(file_get_contents($certfile));
    // Wenn es in weniger als einem Monat abläuft, erneuern
    $renewafter = $certdata['validTo_time_t']-(86400*$this->days_expiration_alert);
    if (time() > $renewafter || $force) {
        // Schwellenwert erreicht oder Force-Flag -> Erneuerung (Renew)
        $needsgen = true;
    }
}
```

## 2. Zentrale Funktionen und Code-Stellen

### Let's Encrypt (LE)

#### `Certman::updateLE($host, $settings, $staging, $force)`
Dies ist die Hauptfunktion für alle Let's Encrypt Operationen.
- **Ort:** `Certman.class.php` (Zeile 789)
- **Ausführung:** Wenn `$needsgen` auf `true` ermittelt wurde (Logik-Check ca. Zeile 828), wird der ACME-Client (`Lescript`) initialisiert und die Methode `$le->signDomains($san)` aufgerufen (Zeile 928). Dies stößt den eigentlichen Request bei Let's Encrypt an.

#### `Certman::checkUpdateCertificates($force)`
Diese Funktion wird automatisch (z.B. per Cron) aufgerufen, um alle verwalteten Zertifikate zu prüfen.
- **Ort:** `Certman.class.php` (Zeile 599)
- **Ablauf:** Sie iteriert über alle Zertifikate in der Datenbank. Für LE-Zertifikate prüft sie das Ablaufdatum und ruft bei Bedarf `updateLE` auf (Zeile 631 für bereits abgelaufene Zertifikate, Zeile 674 für bald ablaufende oder erzwungene Updates).

### Trigger-Punkte

1.  **Web GUI (Neu erstellen):**
    - Wenn ein Benutzer ein neues LE-Zertifikat anlegt.
    - **Code:** `Certman::doConfigPageInit` (Zeile 131) -> `case "add"` (Zeile 286) -> `case "le"` (Zeile 288) ruft `updateLE` auf (Zeile 312).
2.  **Web GUI (Bearbeiten/Manuelles Update):**
    - Wenn ein Benutzer auf "Update" klickt oder Einstellungen ändert.
    - **Code:** `Certman::doConfigPageInit` (Zeile 131) -> `case "edit"` (Zeile 153) -> `case "le"` (Zeile 195) ruft `updateLE` auf (Zeile 232).
3.  **CLI / Cronjob:**
    - Befehl: `fwconsole certificates --updateall`
    - **Code:** `Console/Certman.class.php` (Zeile 234) ruft `Certman::checkUpdateCertificates()` auf (Zeile 239).

## 3. Andere Zertifikatstypen

Bei anderen Typen ist die Unterscheidung weniger komplex, da sie meist manuell gesteuert werden:

-   **Self-Signed:** Werden über `generateCertificate` (Zeile 1523) erstellt. Eine "Erneuerung" im Sinne von LE gibt es hier nicht automatisiert; das Zertifikat muss bei Bedarf neu generiert werden.
-   **Uploaded:** Werden über `importCertificate` (Zeile 1106) verarbeitet. Ein "Renew" bedeutet hier schlicht das Hochladen einer neuen Datei über die GUI (`case "edit"` -> `case "up"`).

## Zusammenfassung

| Aktion | Trigger | Funktion | Prüfung |
| :--- | :--- | :--- | :--- |
| **Issue** | GUI (Add) | `updateLE` | `!file_exists($certfile)` |
| **Renew (Auto)** | Cron / CLI | `checkUpdateCertificates` | `time() > $renewafter` |
| **Renew (Force)** | GUI (Edit) / CLI | `updateLE($force=true)` | Parameter `$force` |
