export default {
  helpContent: {
    title: "Journaux système",
    subtitle: "Le journal applicatif du serveur",
    overview: "Relit ce que UCM a écrit, sans accès shell à l'hôte. C'est le journal qui explique un échec de protocole dont aucun enregistrement n'a été créé : une inscription SCEP refusée à la validation est rejetée avant qu'une ligne de demande existe, et n'apparaît donc qu'ici.",
    sections: [
      {
        title: "Sources",
        items: [
          "Application — le journal propre à UCM. Seule cette source porte des composants, imbriqués dessous",
          "Accès — journal d'accès Gunicorn : requêtes HTTP et codes de statut, installations natives uniquement",
          "Erreurs — journal d'erreurs Gunicorn : démarrage des workers et traces non gérées, natives uniquement",
          "Journal — le journal de l'unité systemd, là où l'utilisateur du service peut le lire",
        ]
      },
      {
        title: "Filtres",
        items: [
          "Source — quel journal, ou quel composant. Seules les sources réellement présentes sont proposées",
          "Niveau de journal — un plancher, pas une correspondance exacte : WARNING montre aussi erreurs et critiques",
          "Recherche — insensible à la casse, sur le message et le nom du composant",
          "Date — une fenêtre De/À, appliquée côté serveur",
          "Lignes — combien de lignes correspondantes renvoyer, la plus récente en dernier",
        ]
      },
      {
        title: "Journaux en direct",
        items: [
          "Interroge toutes les cinq secondes et garde la ligne la plus récente en vue",
          "Remonter dans l'historique arrête le suivi, pour ne pas interrompre la lecture",
          "Efface la fenêtre de dates, qui pose la question inverse",
        ]
      },
    ],
    tips: [
      "Les horodatages sont à l'heure locale du serveur sans décalage ; la zone est indiquée en bas de page",
      "Une ligne sans format connu est tout de même affichée, sans niveau, plutôt que masquée",
      "Une trace est une entrée, pas une par ligne : sélectionnez-la pour tout lire",
      "Les secrets sont expurgés côté serveur avant toute sortie du processus",
    ],
    warnings: [
      "La liste des composants ne reflète que les lignes lues, pas tous les sous-systèmes",
      "La lecture est réservée aux administrateurs et n'est volontairement pas auditée : la piste d'audit écrit dans ce même journal",
    ],
  }
}
