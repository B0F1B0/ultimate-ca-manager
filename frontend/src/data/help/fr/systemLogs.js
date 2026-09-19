export default {
  helpContent: {
    title: "Journaux système",
    subtitle: "Le journal applicatif du serveur",
    overview: "Relit ce que UCM a écrit, sans accès shell à l'hôte. C'est le journal qui explique un échec de protocole dont aucun enregistrement n'a été créé : une inscription SCEP refusée à la validation est rejetée avant qu'une ligne de demande existe, et n'apparaît donc qu'ici.",
    sections: [
      {
        title: "Sources",
        items: [
          "Application — le journal propre à UCM. Seule source à porter des composants",
          "Accès — journal d'accès Gunicorn : requêtes HTTP et codes de statut, installations natives uniquement",
          "Erreurs — journal d'erreurs Gunicorn : démarrage des workers et traces non gérées, natives uniquement",
          "Journal — le journal de l'unité systemd, là où l'utilisateur du service peut le lire",
        ]
      },
      {
        title: "Filtres",
        items: [
          "Source — Quel journal est lu. Seules les sources réellement présentes sont proposées",
          "Composant — Un sous-système du journal applicatif, ou tous. Tous y figurent, pas seulement ceux affichés",
          "Niveau de journal — Un plancher, pas une correspondance exacte : WARNING montre aussi erreurs et critiques",
          "Recherche — Insensible à la casse, sur le message et le nom du composant",
          "Exclure — Retire les lignes correspondantes : le plus rapide pour faire taire un battement",
          "Expressions régulières — Traite recherche et exclusion comme des motifs ; un motif inachevé ne correspond à rien",
          "Date — Une fenêtre De/À, appliquée sur le serveur",
          "Lignes — Combien de lignes correspondantes renvoyer, de la plus récente à la plus ancienne",
        ]
      },
      {
        title: "Journaux en direct",
        items: [
          "Interroge toutes les cinq secondes ; la ligne la plus récente est la première",
          "Efface la fenêtre de dates, qui pose la question inverse",
        ]
      },
    ],
    tips: [
      "Les horodatages sont à l'heure locale du serveur sans décalage ; la zone est indiquée en bas de page",
      "Une ligne sans format connu est tout de même affichée, sans niveau, plutôt que masquée",
      "Une trace est une entrée, pas une par ligne : la cellule du message se replie et l'affiche en entier",
      "Les secrets sont expurgés côté serveur avant toute sortie du processus",
    ],
    warnings: [
      "Un composant sans écriture récente reste listé : le choisir peut ne rien renvoyer",
      "La lecture est réservée aux administrateurs et n'est volontairement pas auditée : la piste d'audit écrit dans ce même journal",
    ],
  },
  helpGuides: {
    title: "Journaux système",
    content: `
## Vue d'ensemble

Relit ce que UCM a écrit, sans accès shell à l'hôte. C'est le journal qui explique un échec dont aucun enregistrement n'a été créé : une inscription SCEP refusée à la validation est rejetée avant qu'une ligne de demande existe.

Les lignes sont affichées de la plus récente à la plus ancienne, et tous les filtres s'appliquent côté serveur.

## Sources

**Source** et **Composant** sont dans le panneau de filtres : choisissez le journal, puis restreignez à un sous-système.

- **Application** : le journal propre à UCM. Seule source à porter des composants.
- **Accès** : journal d'accès Gunicorn, installations natives uniquement.
- **Erreurs** : journal d'erreurs Gunicorn, installations natives uniquement.
- **Journal** : le journal systemd, lorsqu'il est lisible.

### Composants

**Tous les composants** désigne le journal applicatif entier. La liste contient tous les sous-systèmes depuis lesquels UCM peut écrire, même restés silencieux. En choisir un prend tout ce qui est dessous : \`services\` couvre \`services.scep.scep_service\`.

## Filtres

### Niveau de journal
Un plancher, pas une correspondance exacte : **WARNING** montre aussi erreurs et critiques. Une ligne sans niveau lisible n'est jamais masquée.

### Recherche et Exclure
Les deux parcourent le message et le nom du composant. **Exclure** retire ce qui correspond, le moyen le plus rapide de faire taire un battement qui revient chaque minute. **Expressions régulières** traite les deux comme des motifs ; un motif inachevé ne correspond à rien plutôt que d'échouer.

### Date
Une fenêtre De/À. Une ligne sans horodatage en est exclue : une fenêtre demande un instant.

### Lignes
Combien de lignes correspondantes renvoyer, de 100 à 5000.

## Journaux en direct

Interroge toutes les cinq secondes et efface la fenêtre de dates, qui pose la question inverse.

## Copier

**Tout copier** prend toutes les lignes ; cocher une ligne donne **Copier la sélection**. La copie garde la forme du journal.

## Lire le pied de page

- **Affichage des N lignes les plus récentes sur M correspondantes** — davantage correspondaient que ne l'autorise **Lignes**.
- **Seule la partie la plus récente du fichier a été lue** — le fichier dépasse la fenêtre lue.

Les horodatages ne portent pas de décalage : c'est l'heure locale du serveur, la zone est indiquée à côté du chemin.

## Accès

Administrateurs uniquement, et volontairement non audité : la piste d'audit s'écrit dans ce même journal.
`
  }
}
