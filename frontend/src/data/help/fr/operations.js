export default {
  helpContent: {
    title: 'Opérations',
    subtitle: 'Importation, exportation et actions en masse',
    overview: 'Centre d\'opérations centralisé. Importez des certificats depuis des fichiers ou OPNsense, exportez des bundles aux formats PEM/P7B et effectuez des actions en masse sur tous les types de ressources avec recherche et filtres intégrés.',
    sections: [
      {
        title: 'Onglets latéraux',
        items: [
          { label: 'Importation', text: 'Importation intelligente avec détection automatique du format, plus synchronisation OPNsense pour récupérer les certificats des pare-feu' },
          { label: 'Exportation', text: 'Télécharger des bundles de certificats par type de ressource au format PEM ou P7B via des cartes d\'action' },
          { label: 'Actions en masse', text: 'Sélectionner un type de ressource et effectuer des opérations par lots sur plusieurs éléments' },
        ]
      },
      {
        title: 'Actions en masse',
        items: [
          { label: 'Certificats', text: 'Révoquer, renouveler, supprimer ou exporter, filtrer par statut et CA émettrice' },
          { label: 'CA', text: 'Supprimer ou exporter des autorités de certification' },
          { label: 'CSR', text: 'Signer avec une CA ou supprimer les requêtes en attente' },
          { label: 'Modèles', text: 'Supprimer des modèles de certificats' },
          { label: 'Utilisateurs', text: 'Supprimer des comptes utilisateurs' },
        ]
      },
    ],
    tips: [
      'Utilisez les puces de ressources pour basculer rapidement entre les types de ressources',
      'La recherche et les filtres intégrés (Statut, CA) permettent d\'affiner les éléments sans quitter la barre d\'outils',
      'Basculez entre les modes d\'affichage Tableau et Panier (panneau de transfert) sur ordinateur',
      'Prévisualisez les changements avant de confirmer les opérations en masse',
    ],
    warnings: [
      'La suppression en masse est irréversible : créez toujours une sauvegarde d\'abord',
      'La révocation en masse publiera des CRL mises à jour pour toutes les CA concernées',
    ],
  },
  helpGuides: {
    title: 'Opérations',
    content: `
## Vue d'ensemble

Opérations en masse et gestion des données. Effectuez des actions par lots sur plusieurs ressources simultanément.

## Onglet Importation/Exportation

Identique à la page Importation & Exportation : assistant d'importation intelligente et fonctionnalité d'export en masse.

## Onglet OPNsense

Identique à l'intégration OPNsense de la page Importation & Exportation : connectez-vous, parcourez et importez depuis OPNsense.

## Actions en masse

Effectuez des opérations par lots sur plusieurs ressources à la fois.

### Comment ça fonctionne
1. Sélectionnez le **type de ressource** (Certificats, CA, CSR, Modèles, Utilisateurs)
2. Parcourez les éléments disponibles dans le **panneau de gauche**
3. Déplacez les éléments vers le **panneau de droite** (sélectionné) à l'aide des flèches de transfert
4. Choisissez l'**action** à effectuer
5. Confirmez et exécutez

### Actions disponibles par ressource

#### Certificats
- **Révocation en masse** : Révoquer plusieurs certificats à la fois
- **Renouvellement en masse** : Renouveler plusieurs certificats
- **Exportation en masse** : Télécharger les certificats sélectionnés en bundle
- **Suppression en masse** : Supprimer définitivement les certificats sélectionnés

#### CA
- **Exportation en masse** : Télécharger les CA sélectionnées
- **Suppression en masse** : Supprimer les CA sélectionnées (ne doivent pas avoir d'enfants)

#### CSR
- **Signature en masse** : Signer plusieurs CSR avec une CA sélectionnée
- **Suppression en masse** : Supprimer les CSR sélectionnées

#### Modèles
- **Exportation en masse** : Exporter au format JSON
- **Suppression en masse** : Supprimer les modèles sélectionnés

#### Utilisateurs
- **Désactivation en masse** : Désactiver les comptes utilisateurs sélectionnés
- **Suppression en masse** : Supprimer définitivement les utilisateurs sélectionnés

> ⚠ Les opérations en masse sont irréversibles. Créez toujours une sauvegarde avant d'effectuer des suppressions ou révocations en masse.

> 💡 Utilisez la recherche et le filtre dans le panneau de gauche pour trouver rapidement des éléments spécifiques.
`
  }
}
