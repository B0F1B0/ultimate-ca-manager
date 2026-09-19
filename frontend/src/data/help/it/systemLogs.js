export default {
  helpContent: {
    title: "Log di sistema",
    subtitle: "Il log applicativo del server",
    overview: "Rilegge ciò che UCM ha scritto, senza accesso shell all'host. È il log che spiega un errore di protocollo per cui non è mai stato creato un record: un'iscrizione SCEP rifiutata in validazione viene scartata prima che esista una riga di richiesta, e compare solo qui.",
    sections: [
      {
        title: "Origini",
        items: [
          "Applicazione — il log di UCM. Solo questa origine ha componenti, annidati sotto di essa",
          "Accessi — log di accesso di Gunicorn: richieste HTTP e codici di stato, solo installazioni native",
          "Errori — log errori di Gunicorn: avvio dei worker e traceback non gestiti, solo native",
          "Journal — il journal dell'unità systemd, dove l'utente del servizio può leggerlo",
        ]
      },
      {
        title: "Filtri",
        items: [
          "Origine — quale log, o quale componente. Sono offerte solo le origini realmente presenti",
          "Livello di log — una soglia, non una corrispondenza esatta: WARNING mostra anche errori e critici",
          "Cerca — senza distinzione di maiuscole, su messaggio e nome del componente",
          "Data — una finestra Da/A, applicata sul server",
          "Righe — quante righe corrispondenti restituire, la più recente per ultima",
        ]
      },
      {
        title: "Log in tempo reale",
        items: [
          "Interroga ogni cinque secondi e tiene in vista la riga più recente",
          "Scorrere indietro nella cronologia interrompe il seguimento, per non disturbare la lettura",
          "Azzera la finestra temporale, che pone la domanda opposta",
        ]
      },
    ],
    tips: [
      "Gli orari sono nell'ora locale del server senza offset; la zona è indicata a piè di pagina",
      "Una riga senza formato noto viene comunque mostrata, senza livello, invece di essere nascosta",
      "Un traceback è una voce sola, non una per riga: selezionalo per leggerlo tutto",
      "I segreti sono oscurati sul server prima che qualcosa esca dal processo",
    ],
    warnings: [
      "L'elenco dei componenti riflette solo le righe lette, non ogni sottosistema",
      "La lettura è riservata agli amministratori e non è volutamente sottoposta ad audit: la traccia di audit scrive in questo stesso log",
    ],
  }
}
