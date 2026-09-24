# Vérification de la signature d’expéditeur

Date : 23 septembre 2026.

- `npm test` : 18 tests réussis. Vérification du chiffrement/déchiffrement signé v3, de l’identité publique, des altérations de signature/enveloppe, du contrôle d’une clé d’expéditeur attendue et des sauvegardes privées v1/v2.
- `node --check` sur `script.js`, `crypto-engine.js` et `tests/browser.cjs` : réussi.
- `git diff --check` : réussi.
- Le parcours navigateur Playwright n'a pas pu être exécuté : Playwright est disponible dans l'environnement, mais aucun binaire Chromium n'est installé. Le test couvre le flux complet, incluant la vérification de l'expéditeur quand Chromium est disponible.

Aucune publication ni modification du dépôt GitHub distant n'a été effectuée. Ces tests ne constituent pas un audit cryptographique indépendant et ne garantissent pas l'intégrité d'un futur hébergement ou du système de l'utilisateur.

## Détails du changement

Les messages v3 sont signés avec la clé privée ECDSA P-256 de l'expéditeur. Ils embarquent la signature et la clé publique correspondante ; la clé privée ne quitte pas l'appareil. Le destinataire peut vérifier la signature et, en important l'identité publique JSON attendue, contrôler que la signature correspond à l'empreinte reçue par un canal indépendant.

Les sauvegardes v2 protègent ensemble les clés privées RSA et ECDSA. Les sauvegardes antérieures v1 (RSA seulement) et les PEM privés PKCS#8 restent importables ; le chargement d'une ancienne clé crée une nouvelle clé de signature qu'il faut sauvegarder.
