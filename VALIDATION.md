# Vérification de la migration Web Crypto

Date : 23 septembre 2026. Version initiale analysée : `c11622378bee664df1fce9f4ac9562f36ae6be82`.

- 15 tests Node.js réussis : génération RSA, import/export PEM, messages Unicode et espaces exacts, taille maximale, aléatoire par message, mauvais destinataire, altération du contenu et des métadonnées, formats invalides, compatibilité Fernet issue du Python historique, sauvegardes protégées, mauvaise phrase secrète, validation des types/tailles de clés et politique CSP.
- Parcours complet dans Chromium 153, via Playwright : création de clés 3072 bits, téléchargement public, sauvegarde privée chiffrée, chiffrement/déchiffrement v2, verrouillage, restauration de sauvegarde, import d'une clé historique et déchiffrement Fernet.
- Quatre requêtes au chargement : HTML, CSS, deux modules JavaScript locaux. **Aucune requête supplémentaire pendant les opérations sensibles**, exécutées avec le réseau du navigateur coupé.
- Vérification distincte d'un `fetch` de test, après remise du réseau : bloqué par la politique CSP, même vers le site d'origine.
- Aucun cookie, entrée localStorage/sessionStorage ou base IndexedDB après le parcours. Aucune erreur JavaScript de page.
- Captures ordinateur (1360 px) et mobile (390 px) inspectées. Aucun débordement horizontal sur mobile.

Ces vérifications couvrent la version livrée et le navigateur testé ; elles ne constituent pas un audit cryptographique indépendant et ne garantissent pas l'intégrité d'un futur hébergement ou du système de l'utilisateur.

Aucune publication ni modification du dépôt GitHub distant n'a été effectuée.

## Correctif d’import des clés privées

Défaut reproduit sur les fichiers de `origin/main` au commit `caddfbc` : sélectionner la sauvegarde JSON avant de saisir la phrase déclenchait immédiatement un échec et effaçait la sélection du fichier.

Correction : sélection distincte du déclenchement d’import ; bouton explicite, validation avec Entrée, conservation du fichier après un échec, retour d’erreur dans le panneau d’import et état de la clé dans le panneau de déchiffrement. Les formats PEM non pris en charge sont maintenant identifiés clairement. Le moteur cryptographique reste inchangé.
