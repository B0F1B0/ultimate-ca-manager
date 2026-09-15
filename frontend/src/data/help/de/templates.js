export default {
  helpContent: {
    title: 'Zertifikatstemplates',
    subtitle: 'Wiederverwendbare Zertifikatsprofile',
    overview: 'Definieren Sie wiederverwendbare Zertifikatsprofile mit vorkonfigurierten Betreffsfeldern, Key Usage, Extended Key Usage, Gültigkeitszeiträumen und anderen Erweiterungen. Wenden Sie Templates bei der Ausstellung oder Signierung von Zertifikaten an.',
    sections: [
      {
        title: 'Template-Typen',
        definitions: [
          { term: 'Endentität', description: 'Für Server-, Client-, Code-Signierungs- und E-Mail-Zertifikate' },
          { term: 'CA', description: 'Zum Erstellen von Intermediate-Zertifizierungsstellen' },
        ]
      },
      {
        title: 'Funktionen',
        items: [
          { label: 'Betreffsstandards', text: 'Organisation, OU, Land, Bundesland, Stadt vorausfüllen' },
          { label: 'Key Usage', text: 'Digital Signature, Key Encipherment, usw.' },
          { label: 'Extended Key Usage', text: 'Server Auth, Client Auth, Code Signing, Email Protection' },
          { label: 'Gültigkeit', text: 'Standard-Gültigkeitsdauer in Tagen' },
          { label: 'Duplizieren', text: 'Ein vorhandenes Template klonen und modifizieren' },
          { label: 'Import/Export', text: 'Templates als JSON-Dateien zwischen UCM-Instanzen teilen' },
        ]
      },
      {
        title: 'Windows-Autoregistrierung',
        items: [
          { label: 'Autoregistrierung erlauben', text: 'Das Template als autoEnroll=true in der Certificate Enrollment Policy ausweisen, damit GPO/Kerberos-Clients es bei der Anmeldung automatisch anfordern. Standardmäßig aus, manuelle Registrierung bleibt auch ohne dieses Flag möglich' },
          { label: 'Betreff aus Active Directory ableiten', text: 'Betreff und SAN aus dem AD-Objekt des Anfragenden ableiten (über den AD-Connector), statt sie vom Client zu verlangen, für unbeaufsichtigte GPO-Autoregistrierung' },
          { label: 'Registrierung auf AD-Gruppe beschränken', text: 'Nur Mitglieder der konfigurierten AD-Gruppe (einschließlich verschachtelter Mitgliedschaften) dürfen über den Kerberos-Endpunkt registrieren. Leer = jeder authentifizierte Principal. Auf dem Benutzername/Passwort-Endpunkt nicht durchgesetzt' },
          { label: 'Gepinnte Betreffsfelder', text: 'C/ST/L/O/OU-Werte auf jedem über WSTEP ausgestellten Zertifikat erzwingen, sie überschreiben CSR oder AD-Ableitung für diese Felder. CN und SAN sind nie betroffen, lassen Sie ein Feld leer, um es dynamisch zu halten' },
        ]
      },
    ],
    tips: [
      'Erstellen Sie separate Templates für TLS-Server, Clients und Code-Signierung',
      'Verwenden Sie die Duplizieren-Aktion, um schnell Varianten eines Templates zu erstellen',
      'Templates mit Autoregistrierungs-Flags zeigen AD- / Auto- / ACL- / Pinned-Badges in der Liste',
    ],
  },
  helpGuides: {
    title: 'Zertifikatstemplates',
    content: `
## Übersicht

Templates definieren wiederverwendbare Zertifikatsprofile. Anstatt Key Usage, Extended Key Usage, Gültigkeit und Betreffsfelder jedes Mal manuell zu konfigurieren, wenden Sie ein Template an, um alles vorzufüllen.

## Template-Typen

### Endentitäts-Templates
Für Serverzertifikate, Client-Zertifikate, Code-Signierung und E-Mail-Schutz. Diese Templates setzen typischerweise:
- **Key Usage**: Digital Signature, Key Encipherment
- **Extended Key Usage**: Server Auth, Client Auth, Code Signing, Email Protection

### CA-Templates
Zum Erstellen von Intermediate-CAs. Diese setzen:
- **Key Usage**: Certificate Sign, CRL Sign
- **Basic Constraints**: CA:TRUE, optionale Pfadlänge

## Template erstellen

1. Klicken Sie auf **Template erstellen**
2. Geben Sie einen **Namen** und eine optionale Beschreibung ein
3. Wählen Sie den Template-**Typ** (Endentität oder CA)
4. Konfigurieren Sie **Betreffsstandards** (O, OU, C, ST, L)
5. Wählen Sie **Key Usage**-Flags
6. Wählen Sie **Extended Key Usage**-Werte
7. Legen Sie die **Standard-Gültigkeitsdauer** in Tagen fest
8. Klicken Sie auf **Erstellen**

## Templates verwenden

Wählen Sie beim Ausstellen eines Zertifikats oder Signieren eines CSR ein Template aus der Dropdown-Liste. Das Template füllt vor:
- Betreffsfelder (die Sie überschreiben können)
- Key Usage und Extended Key Usage
- Gültigkeitsdauer

## Windows-Autoregistrierungs-Flags

Templates tragen drei Opt-in-Flags für die Windows-Autoregistrierungsprotokolle (XCEP/WSTEP, konfiguriert unter **Einstellungen → Windows-Autoregistrierung**):

- **Autoregistrierung erlauben**: Das Template als \`autoEnroll=true\` in der Certificate Enrollment Policy ausweisen, damit GPO/Kerberos-authentifizierte Clients es bei der Anmeldung automatisch und ohne Benutzeraktion anfordern. Standardmäßig aus: wie bei echtem ADCS kann ein Template auch ohne dieses Flag manuell registriert werden (MMC „Neues Zertifikat anfordern", \`certreq\`), da Enroll und Autoenroll getrennte Berechtigungen sind.
- **Betreff aus Active Directory ableiten**: Für unbeaufsichtigte GPO-Autoregistrierung: Betreff und SAN des Zertifikats aus dem AD-Objekt des Anfragenden ableiten (über den AD-Connector), statt sie vom Client zu verlangen.
- **Registrierung auf AD-Gruppe beschränken**: Nur Principals, die der konfigurierten Active-Directory-Gruppe angehören (einschließlich verschachtelter Mitgliedschaften), dürfen dieses Template über den Kerberos-authentifizierten Endpunkt registrieren. Geben Sie einen Gruppennamen oder vollständigen DN ein; leer lassen, um jeden authentifizierten Principal zuzulassen: entsprechend dem ADCS-Standardverhalten. Auf dem Benutzername/Passwort-Endpunkt nicht durchgesetzt, da dort keine Identität pro Anfrage geprüft werden kann.

Templates mit diesen Flags zeigen **AD**-, **Auto**- und **ACL**-Badges in der Template-Liste.

## Gepinnte Betreffsfelder

Ein Template kann die organisatorischen Betreffsfelder: **C, ST, L, O, OU**: für über WSTEP ausgestellte Zertifikate **pinnen**. Ein gepinnter Wert wird auf jedes ausgestellte Zertifikat erzwungen und überschreibt, was der CSR des Clients oder die Active-Directory-Ableitung für dieses Feld liefert.

- **Common Name und Subject Alternative Name sind nie betroffen**: sie bleiben pro Anfragendem dynamisch
- Lassen Sie ein Feld leer, um es dynamisch zu halten
- Templates mit gepinnten Feldern zeigen ein **Pinned**-Badge, und die gepinnten Werte erscheinen im Template-Detailbereich

Nutzen Sie dies, um eine einheitliche organisatorische Identität (z.B. ein festes \`O\` und \`C\`) über eine autoregistrierte Flotte hinweg zu garantieren, unabhängig davon, was jeder Windows-Client übermittelt.

## Templates duplizieren

Klicken Sie auf **Duplizieren**, um eine Kopie eines vorhandenen Templates zu erstellen. Modifizieren Sie die Kopie, ohne das Original zu beeinflussen.

## Import & Export

### Export
Exportieren Sie Templates als JSON zum Teilen zwischen UCM-Instanzen.

### Import
Importieren Sie aus:
- **JSON-Datei**: Template-JSON-Datei hochladen
- **JSON einfügen**: JSON direkt in den Textbereich einfügen

## Gängige Template-Beispiele

### TLS-Server
- Key Usage: Digital Signature, Key Encipherment
- Extended Key Usage: Server Authentication
- Gültigkeit: 365 Tage

### Client-Authentifizierung
- Key Usage: Digital Signature
- Extended Key Usage: Client Authentication
- Gültigkeit: 365 Tage

### Code-Signierung
- Key Usage: Digital Signature
- Extended Key Usage: Code Signing
- Gültigkeit: 365 Tage
`
  }
}
