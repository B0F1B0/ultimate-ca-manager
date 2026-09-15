export default {
  helpContent: {
    title: 'Zertifikatserkennung',
    subtitle: 'TLS-Zertifikate in Ihrem Netzwerk finden',
    overview: 'Scannen Sie Ihr Netzwerk, um auf Servern und Endpunkten bereitgestellte TLS-Zertifikate zu finden und mit Ihrem verwalteten PKI-Bestand abzugleichen. Finden Sie nicht erfasste Zertifikate, erkennen Sie Änderungen und behalten Sie ablaufende Zertifikate außerhalb der Kontrolle von UCM im Blick.',
    sections: [
      {
        title: 'Tabs',
        items: [
          { label: 'Erkannt', text: 'Alle von Scans gefundenen Zertifikate mit Status, Ablauf und Endpunktdetails' },
          { label: 'Profile', text: 'Gespeicherte Scan-Konfigurationen, Ziele, Ports, Zeitplan, Benachrichtigungen' },
          { label: 'Verlauf', text: 'Vergangene Scan-Läufe mit Dauer, gescannten Zielen und gefundenen Zertifikaten' },
        ]
      },
      {
        title: 'Scannen',
        items: [
          { label: 'Schnellscan', text: 'Ad-hoc-Scan ohne Profil zu speichern, Ziele und Ports eingeben, Ergebnisse werden live gestreamt' },
          { label: 'Ziele', text: 'Eines pro Zeile: Hostname, IP, CIDR-Subnetz (192.168.1.0/24) oder host:port (10.0.0.1:8443)' },
          { label: 'Ports', text: 'Kommagetrennte TCP-Ports (z. B. 443, 8443, 636) oder die Voreinstellung mit gängigen Ports' },
          { label: 'Erweiterte Optionen', text: 'Reverse-DNS-Auflösung (PTR-Einträge), Timeout und Parallelität' },
          { label: 'Zeitplan', text: 'Profile laufen manuell oder automatisch alle 1h / 6h / 12h / 24h / 7d' },
          { label: 'Benachrichtigungen', text: 'E-Mail-Alarme bei neuen Zertifikaten, Zertifikatsänderungen oder bevorstehendem Ablauf' },
        ]
      },
      {
        title: 'Ergebnisstatus',
        items: [
          { label: 'Verwaltet', text: 'Der SHA-256-Fingerabdruck des Zertifikats stimmt mit einem Zertifikat im UCM-Bestand überein' },
          { label: 'Nicht verwaltet', text: 'Im Netzwerk gefunden, aber nicht im Bestand, ein Kandidat für die Übernahme in die Verwaltung' },
          { label: 'Fehler', text: 'Der Endpunkt konnte nicht gescannt werden, der Fehlerhinweis unterscheidet abgelehnte Verbindungen, DNS-, Timeout- und TLS/SNI-Fehler; einzeln oder alle auf einmal wiederholen' },
          { label: 'Geändert', text: 'Ein Endpunkt, der ein anderes Zertifikat als beim vorherigen Scan präsentiert, wird mit einem Zeitstempel „Zuletzt geändert" markiert' },
        ]
      },
    ],
    tips: [
      'Filtern Sie Ergebnisse mit den Status-Pills: Verwaltet, Nicht verwaltet, Fehler, Abgelaufen, Läuft bald ab',
      'Exportieren Sie erkannte Zertifikate als CSV oder JSON: aktive Filter gelten für den Export',
      'Planen Sie einen täglichen Scan Ihrer Server-Subnetze mit aktivierter Benachrichtigung über neue Zertifikate',
    ],
    warnings: [
      'Das Ausführen von Scans und die Verwaltung von Profilen erfordern Admin-Berechtigungen; Subnetze sind auf 1024 Adressen (/22) begrenzt',
    ],
  },
  helpGuides: {
    title: 'Zertifikatserkennung',
    content: `
## Übersicht

Die Zertifikatserkennung scannt Ihr Netzwerk, um auf Servern und Endpunkten bereitgestellte TLS-Zertifikate zu finden und mit Ihrem verwalteten PKI-Bestand abzugleichen. Nutzen Sie sie, um nicht erfasste Zertifikate zu finden, Änderungen zu erkennen und ablaufende Zertifikate außerhalb der Kontrolle von UCM im Blick zu behalten.

## Tabs

### Erkannt
Alle von Scans gefundenen Zertifikate mit Status, Ablauf und Endpunktdetails. Klicken Sie auf eine Zeile, um das Detailpanel mit Zertifikatsinfos, Subject Alternative Names und Scan-Verlauf (zuerst gesehen, zuletzt gesehen, zuletzt geändert) zu öffnen.

### Profile
Gespeicherte Scan-Konfigurationen für wiederkehrende Scans. Ziele, Ports, Zeitplan und Benachrichtigungen.

### Verlauf
Vergangene Scan-Läufe mit Dauer, gescannten Zielen, gefundenen Zertifikaten und wer den Lauf ausgelöst hat.

## Schnellscan

Führen Sie einen Ad-hoc-Scan aus, ohne ein Profil zu speichern:

1. Klicken Sie auf **Schnellscan**
2. Geben Sie **Ziele** ein: eines pro Zeile: Hostname, IP, CIDR-Subnetz (\`192.168.1.0/24\`) oder \`host:port\` (\`10.0.0.1:8443\`)
3. Geben Sie **Ports** ein: kommagetrennte TCP-Ports (z. B. \`443, 8443, 636\`) oder wählen Sie die Voreinstellung mit gängigen Ports
4. Passen Sie optional die **erweiterten Optionen** an. Reverse-DNS-Auflösung (PTR-Einträge), Timeout, Parallelität
5. Klicken Sie auf **Scan starten**: der Fortschritt wird live über WebSocket aktualisiert

## Scan-Profile

Profile speichern eine Zielkonfiguration zur wiederholten Verwendung:

- **Ziele und Ports**: gleiche Formate wie beim Schnellscan
- **Zeitplan**: manuell oder automatisch alle 1h / 6h / 12h / 24h / 7d
- **Benachrichtigungen**: E-Mail-Alarme, wenn neue Zertifikate erkannt werden, wenn sich ein Zertifikat auf einem Endpunkt ändert oder wenn erkannte Zertifikate bald ablaufen

Führen Sie ein Profil bei Bedarf mit **Scan** aus oder lassen Sie den Scheduler es im konfigurierten Intervall ausführen.

## Ergebnisstatus

- **Verwaltet**: Der SHA-256-Fingerabdruck des Zertifikats stimmt mit einem Zertifikat im UCM-Bestand überein
- **Nicht verwaltet**: Im Netzwerk gefunden, aber nicht im Bestand: ein Kandidat für die Übernahme in die Verwaltung
- **Fehler**: Der Endpunkt konnte nicht gescannt werden; die Fehlerspalte zeigt einen Hinweis (Verbindung abgelehnt, DNS-Fehler, Timeout, TLS-Handshake-/SNI-Problem)

### Änderungserkennung
Wenn ein Endpunkt ein anderes Zertifikat als beim vorherigen Scan präsentiert, wird die Änderung aufgezeichnet (vorheriger Fingerabdruck bleibt erhalten, Zeitstempel **Zuletzt geändert**) und kann eine Benachrichtigung auslösen.

## Filtern & Export

- **Status-Filter-Pills**: Verwaltet, Nicht verwaltet, Fehler, Abgelaufen, Läuft bald ab
- **Profilfilter**: Ergebnisse auf ein Scan-Profil beschränken
- **Export**: Erkannte Zertifikate als CSV oder JSON herunterladen (Filter werden angewendet)
- **Wiederholen**: Einzelne Fehlerziele erneut scannen oder **Alle Fehler wiederholen** auf einmal
- **DNS auflösen**: Massenhafte Reverse-DNS-Auflösung für erkannte IPs

## Grenzen & Sicherheit

- Subnetze sind auf 1024 Adressen begrenzt (entspricht einem IPv4-/22); bis zu 1000 Ziele pro Profil-Scan
- Private RFC1918-Bereiche und Loopback sind scanbar: UCMs On-Prem-Bereitstellungsmodell; Link-Local-, Multicast- und reservierte Bereiche sind blockiert
- Alle Scan-Aktionen werden im Audit-Log protokolliert

## Berechtigungen

- **read:certificates**: Erkannte Zertifikate, Profile und Verlauf anzeigen
- **admin:system**: Profile erstellen/bearbeiten und Scans ausführen
- **delete:certificates**: Erkannte Ergebnisse löschen

> 💡 Planen Sie einen täglichen Scan Ihrer Server-Subnetze und aktivieren Sie die Benachrichtigung über neue Zertifikate, so erwischen Sie Zertifikate, die außerhalb Ihres PKI-Prozesses bereitgestellt wurden.
`
  }
}
