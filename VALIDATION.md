# Vérification de la signature d’expéditeur

Date : 24 septembre 2026.

- `npm test` : 19 tests réussis. Vérification du chiffrement/déchiffrement signé v3, de l’identité publique, des altérations de signature/enveloppe, du contrôle de la clé d’expéditeur attendue, de l’acceptation de la sauvegarde v2 et du rejet de v1 ; le chargement sans phrase secrète et les clés privées PEM sont refusés.
- `node --check` sur `script.js`, `crypto-engine.js` et `tests/browser.cjs` : réussi.
- `git diff --check` : réussi.
- Le parcours navigateur Playwright n'a pas été exécuté dans cette vérification. Le test couvre le flux complet, dont le blocage du bouton d'import tant qu'aucune phrase secrète n'est saisie et le refus d'un PEM privé non chiffré.

Aucune publication ni modification du dépôt GitHub distant n'a été effectuée. Ces tests ne constituent pas un audit cryptographique indépendant et ne garantissent pas l'intégrité d'un futur hébergement ou du système de l'utilisateur.

## Détails du changement

Les messages v3 sont signés avec la clé privée ECDSA P-256 de l'expéditeur. Ils embarquent la signature et la clé publique correspondante ; la clé privée ne quitte pas l'appareil. Le destinataire peut vérifier la signature et, en important l'identité publique JSON attendue, contrôler que la signature correspond à l'empreinte reçue par un canal indépendant.

Seule la sauvegarde JSON v2 générée par l'interface est acceptée. Elle protège ensemble les clés privées RSA et ECDSA avec la phrase secrète. Les sauvegardes JSON v1 et tous les PEM privés sont refusés.
