export default {
  helpContent: {
    title: "Systemprotokolle",
    subtitle: "Das Anwendungsprotokoll des Servers",
    overview: "Liest zurück, was UCM selbst geschrieben hat, ohne Shell-Zugriff auf den Host. Dies ist das Protokoll, das einen Protokollfehler erklärt, für den nie ein Datensatz angelegt wurde: Eine SCEP-Anmeldung, die bei der Validierung abgelehnt wird, wird verworfen, bevor eine Anfragezeile existiert, und erscheint daher nur hier.",
    sections: [
      {
        title: "Quellen",
        items: [
          "Anwendung — UCMs eigenes Protokoll. Nur diese Quelle hat Komponenten, die darunter eingerückt erscheinen",
          "Zugriff — Gunicorn-Zugriffsprotokoll: HTTP-Anfragen und Statuscodes, nur native Installationen",
          "Fehler — Gunicorn-Fehlerprotokoll: Worker-Start und nicht behandelte Tracebacks, nur native Installationen",
          "Journal — Das systemd-Unit-Journal, sofern der Dienstbenutzer es lesen darf",
        ]
      },
      {
        title: "Filter",
        items: [
          "Quelle — Welches Protokoll oder welche Komponente. Nur tatsächlich vorhandene Quellen werden angeboten",
          "Protokollstufe — Eine Untergrenze, keine exakte Übereinstimmung: WARNING zeigt auch Fehler und Kritisches",
          "Suche — Groß-/Kleinschreibung egal, über Meldung und Komponentenname",
          "Datum — Ein Von/Bis-Fenster, serverseitig angewendet",
          "Zeilen — Wie viele passende Zeilen zurückgegeben werden, neueste zuletzt",
        ]
      },
      {
        title: "Live-Protokolle",
        items: [
          "Fragt alle fünf Sekunden ab und hält die neueste Zeile im Blick",
          "Das Hochscrollen in den Verlauf beendet das Folgen, damit das Lesen nicht unterbrochen wird",
          "Löscht das Datumsfenster, das die gegenteilige Frage stellt",
        ]
      },
    ],
    tips: [
      "Zeitstempel stehen in der lokalen Zeit des Servers ohne Offset; die Zone wird am Seitenende genannt",
      "Eine Zeile ohne bekanntes Format wird trotzdem angezeigt, ohne Stufe, statt verborgen zu werden",
      "Ein Traceback ist ein Eintrag, nicht einer pro Zeile: auswählen, um alles zu lesen",
      "Geheimnisse werden serverseitig entfernt, bevor etwas den Prozess verlässt",
    ],
    warnings: [
      "Die Komponentenliste zeigt nur, was in den gelesenen Zeilen vorkommt, nicht jedes Subsystem",
      "Das Lesen ist Administratoren vorbehalten und wird bewusst nicht auditiert: der Audit-Trail schreibt in dasselbe Protokoll",
    ],
  }
}
