export default {
  helpContent: {
    title: "Log di sistema",
    subtitle: "Il log applicativo del server",
    overview: "Rilegge ciò che UCM ha scritto, senza accesso shell all'host. È il log che spiega un errore di protocollo per cui non è mai stato creato un record: un'iscrizione SCEP rifiutata in validazione viene scartata prima che esista una riga di richiesta, e compare solo qui.",
    sections: [
      {
        title: "Origini",
        items: [
          "Applicazione: il log di UCM. L'unica origine con componenti",
          "Accessi: log di accesso di Gunicorn, con richieste HTTP e codici di stato, solo installazioni native",
          "Errori: log errori di Gunicorn, con avvio dei worker e traceback non gestiti, solo native",
          "Journal: il journal dell'unità systemd, dove l'utente del servizio può leggerlo",
        ]
      },
      {
        title: "Filtri",
        items: [
          "Origine: quale log viene letto. Sono offerte solo le origini realmente presenti",
          "Componente: un sottosistema del log applicativo, o tutti. Ci sono tutti, non solo quelli a schermo",
          "Livello di log: una soglia, non una corrispondenza esatta. WARNING mostra anche errori e critici",
          "Cerca: senza distinzione fra maiuscole, su messaggio e nome del componente. È testo, non un pattern",
          "Escludi: toglie le righe che corrispondono, il modo più rapido di zittire un battito",
          "Data: una finestra Da/A, applicata sul server",
          "Righe: quante righe corrispondenti restituire, dalla più recente",
        ]
      },
      {
        title: "Log in tempo reale",
        items: [
          "Interroga ogni cinque secondi; la riga più recente è la prima",
          "Azzera la finestra temporale, che pone la domanda opposta",
        ]
      },
    ],
    tips: [
      "Gli orari sono nell'ora locale del server senza offset; la zona è indicata a piè di pagina",
      "Una riga senza formato noto viene comunque mostrata, senza livello, invece di essere nascosta",
      "Un traceback è una voce, non una per riga: la cella del messaggio va a capo e lo mostra intero",
      "I segreti sono oscurati sul server prima che qualcosa esca dal processo",
    ],
    warnings: [
      "Un componente che non scrive da tempo resta in elenco: sceglierlo può non restituire nulla",
      "La lettura è riservata agli amministratori e non è volutamente sottoposta ad audit: la traccia di audit scrive in questo stesso log",
    ],
  },
  helpGuides: {
    title: "Log di sistema",
    content: `
## Panoramica

Rilegge ciò che UCM ha scritto, senza accesso shell all'host. È il log che spiega un errore per cui non è mai stato creato un record: un'iscrizione SCEP rifiutata in validazione viene scartata prima che esista una riga di richiesta.

Le righe sono mostrate dalla più recente e ogni filtro è applicato sul server.

## Origini

**Origine** e **Componente** stanno nel pannello dei filtri: scegli il log, poi restringi a un sottosistema.

- **Applicazione**: il log di UCM. L'unica origine con componenti.
- **Accessi**: log di accesso di Gunicorn, solo installazioni native.
- **Errori**: log errori di Gunicorn, solo installazioni native.
- **Journal**: il journal di systemd, dove è leggibile.

### Componenti

**Tutti i componenti** è l'intero log applicativo. L'elenco contiene ogni sottosistema da cui UCM può scrivere, anche se è rimasto in silenzio. Sceglierne uno prende tutto ciò che sta sotto: \`services\` copre \`services.scep.scep_service\`.

## Filtri

### Livello di log
Una soglia, non una corrispondenza esatta: **WARNING** mostra anche errori e critici. Una riga senza livello leggibile non viene mai nascosta.

### Cerca ed Escludi
Entrambi guardano messaggio e nome del componente. **Escludi** toglie ciò che corrisponde, il modo più rapido di zittire un battito che torna ogni minuto.

Entrambi sono testo letterale e non pattern: \`.*\` corrisponde a quei due caratteri e basta. Un pattern inviato dal browser sarebbe lavoro senza limite per l'unico worker che qui risponde a ogni protocollo.

### Data
Una finestra Da/A. Una riga senza orario ne resta fuori: la finestra chiede un istante.

### Righe
Quante righe corrispondenti restituire, da 100 a 5000.

## Log in tempo reale

Interroga ogni cinque secondi e azzera la finestra temporale, che pone la domanda opposta.

## Copia

**Copia tutto** prende ogni riga; spuntandone una compare **Copia selezionati**. La copia mantiene la forma del log.

## Leggere il piè di pagina

- **Mostrate le N righe più recenti su M corrispondenti**: ne corrispondevano più di quante **Righe** ne consenta.
- **È stata letta solo la parte più recente del file**: il file supera la finestra letta.

Gli orari non portano offset: sono ora locale del server, la zona è indicata accanto al percorso.

## Accesso

Solo amministratori, e volutamente non sottoposto ad audit: la traccia di audit scrive in questo stesso log.
`
  }
}
