export default {
  helpContent: {
    title: "Systemprotokolle",
    subtitle: "Das Anwendungsprotokoll des Servers",
    overview: "Liest zurück, was UCM selbst geschrieben hat, ohne Shell-Zugriff auf den Host. Dies ist das Protokoll, das einen Protokollfehler erklärt, für den nie ein Datensatz angelegt wurde: Eine SCEP-Anmeldung, die bei der Validierung abgelehnt wird, wird verworfen, bevor eine Anfragezeile existiert, und erscheint daher nur hier.",
    sections: [
      {
        title: "Quellen",
        items: [
          "Anwendung — UCMs eigenes Protokoll. Nur diese Quelle hat Komponenten",
          "Zugriff — Gunicorn-Zugriffsprotokoll: HTTP-Anfragen und Statuscodes, nur native Installationen",
          "Fehler — Gunicorn-Fehlerprotokoll: Worker-Start und nicht behandelte Tracebacks, nur native Installationen",
          "Journal — Das systemd-Unit-Journal, sofern der Dienstbenutzer es lesen darf",
        ]
      },
      {
        title: "Filter",
        items: [
          "Quelle — Welches Protokoll gelesen wird. Nur tatsächlich vorhandene Quellen werden angeboten",
          "Komponente — Ein Subsystem des Anwendungsprotokolls oder alle. Aufgeführt sind alle, nicht nur die sichtbaren",
          "Protokollstufe — Eine Untergrenze, keine exakte Übereinstimmung: WARNING zeigt auch Fehler und Kritisches",
          "Suche — Groß-/Kleinschreibung egal, über Meldung und Komponentenname",
          "Ausschließen — Entfernt passende Zeilen: der schnellste Weg, einen Heartbeat stummzuschalten",
          "Reguläre Ausdrücke — Behandelt Suche und Ausschluss als Muster; ein unvollständiges trifft nichts",
          "Datum — Ein Von/Bis-Fenster, serverseitig angewendet",
          "Zeilen — Wie viele passende Zeilen zurückgegeben werden, neueste zuerst",
        ]
      },
      {
        title: "Live-Protokolle",
        items: [
          "Fragt alle fünf Sekunden ab; die neueste Zeile ist die erste",
          "Löscht das Datumsfenster, das die gegenteilige Frage stellt",
        ]
      },
    ],
    tips: [
      "Zeitstempel stehen in der lokalen Zeit des Servers ohne Offset; die Zone wird am Seitenende genannt",
      "Eine Zeile ohne bekanntes Format wird trotzdem angezeigt, ohne Stufe, statt verborgen zu werden",
      "Ein Traceback ist ein Eintrag, nicht einer pro Zeile: die Meldungsspalte bricht um und zeigt ihn ganz",
      "Geheimnisse werden serverseitig entfernt, bevor etwas den Prozess verlässt",
    ],
    warnings: [
      "Eine Komponente, die zuletzt nichts geschrieben hat, steht trotzdem in der Liste: die Auswahl kann leer bleiben",
      "Das Lesen ist Administratoren vorbehalten und wird bewusst nicht auditiert: der Audit-Trail schreibt in dasselbe Protokoll",
    ],
  },
  helpGuides: {
    title: "Systemprotokolle",
    content: `
## Überblick

Liest zurück, was UCM selbst geschrieben hat, ohne Shell-Zugriff auf den Host. Es ist das Protokoll, das einen Fehler erklärt, für den nie ein Datensatz angelegt wurde: Eine bei der Validierung abgelehnte SCEP-Anmeldung wird verworfen, bevor eine Anfragezeile existiert.

Zeilen erscheinen neueste zuerst, und jeder Filter wird auf dem Server angewendet.

## Quellen

**Quelle** und **Komponente** stehen im Filterbereich: erst das Protokoll wählen, dann auf ein Subsystem eingrenzen.

- **Anwendung**: UCMs eigenes Protokoll. Nur diese Quelle hat Komponenten.
- **Zugriff**: Gunicorn-Zugriffsprotokoll, nur native Installationen.
- **Fehler**: Gunicorn-Fehlerprotokoll, nur native Installationen.
- **Journal**: das systemd-Unit-Journal, sofern lesbar.

### Komponenten

**Alle Komponenten** ist das ganze Anwendungsprotokoll. Die Liste enthält jedes Subsystem, aus dem UCM protokollieren kann, auch wenn es zuletzt still war. Eine Auswahl umfasst alles darunter: \`services\` trifft auch \`services.scep.scep_service\`.

## Filter

### Protokollstufe
Eine Untergrenze, keine exakte Übereinstimmung: **WARNING** zeigt auch Fehler und Kritisches. Eine Zeile ohne lesbare Stufe wird nie ausgeblendet.

### Suche und Ausschließen
Beide durchsuchen Meldung und Komponentenname. **Ausschließen** entfernt Treffer — der schnellste Weg, einen minütlichen Heartbeat stummzuschalten. **Reguläre Ausdrücke** behandelt beide als Muster; ein unvollständiges Muster trifft nichts, statt die Anfrage scheitern zu lassen.

### Datum
Ein Von/Bis-Fenster. Eine Zeile ohne Zeitstempel entfällt dabei: Ein Fenster fragt nach einem Zeitpunkt.

### Zeilen
Wie viele passende Zeilen zurückgegeben werden, 100 bis 5000.

## Live-Protokolle

Fragt alle fünf Sekunden ab und löscht das Datumsfenster, das die gegenteilige Frage stellt.

## Kopieren

**Alle kopieren** nimmt jede Zeile; markierte Zeilen ergeben **Auswahl kopieren**. Kopiert wird in der Form des Protokolls.

## Die Fußzeile lesen

- **Es werden die N neuesten von M passenden Zeilen angezeigt** — mehr passten, als die Einstellung **Zeilen** zulässt.
- **Nur der neueste Teil der Datei wurde gelesen** — die Datei ist größer als das gelesene Fenster.

Zeitstempel tragen keinen Offset; sie sind lokale Serverzeit, die Zone steht neben dem Pfad.

## Zugriff

Nur für Administratoren, und bewusst nicht auditiert: Der Audit-Trail schreibt in dasselbe Protokoll.
`
  }
}
