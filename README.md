# Crypto · Chiffrement local

Une page statique en français pour chiffrer et déchiffrer des messages sur votre appareil. Aucun compte, serveur de traitement, Pyodide, CDN, télémétrie ou dépendance JavaScript de production.

## Ouvrir depuis GitHub Pages

Adresse du site : **https://mathiasj06.github.io/crypto_page/**.

GitHub Pages est déjà activé sur le dépôt. Pour remplacer l'ancienne application, publier `index.html`, `style.css`, `script.js` et `crypto-engine.js` à la racine de la branche utilisée par Pages. Le fichier `.nojekyll` permet de servir les fichiers statiques directement. Si la source doit être configurée : **Settings → Pages → Build and deployment → Deploy from a branch → main → / (root)**.

Aucun serveur Python n'est nécessaire pour les visiteurs. GitHub fournit les fichiers statiques, puis le navigateur réalise toutes les opérations sensibles localement. La publication n'ajoute aucun appel réseau à l'application.

Les changements sont préparés pour publication ; le site public reste sur l'ancienne version tant que les nouveaux fichiers n'ont pas été envoyés au dépôt et déployés.

L'utilisation prévue est directement dans le navigateur, à l'adresse GitHub Pages ci-dessus. Aucun lancement local avec Python n'est nécessaire. Après le chargement de la page, les opérations sur les clés et les messages s'effectuent dans le navigateur, sans requête réseau supplémentaire.

## Utilisation

1. **Mes clés** : générez votre identité, composée d'une paire RSA de chiffrement et d'une paire ECDSA de signature. Téléchargez l'identité publique à partager et la sauvegarde privée protégée par une phrase secrète longue et unique (12 caractères minimum). Vérifiez que la sauvegarde est bien enregistrée. La phrase n'est pas récupérable par un service.
2. **Chiffrer** : importez l'identité publique de votre destinataire (ou son ancienne clé publique RSA). Comparez l'empreinte complète avec lui par un autre canal. Saisissez le message, chiffrez, puis copiez ou téléchargez le résultat chiffré pour le transmettre. L'application le signe avec votre clé privée de signature, qui ne quitte jamais l'appareil.
3. **Déchiffrer** : sélectionnez votre sauvegarde privée chiffrée dans « Mes clés », saisissez obligatoirement sa phrase secrète, puis cliquez sur « Importer ma clé privée ». Collez/importez ensuite le message reçu et déchiffrez. La page vérifie la signature et affiche l'empreinte de la clé signataire. Pour vérifier qu'elle appartient bien à la personne attendue, chargez aussi son identité publique ou comparez l'empreinte par un canal sûr. Un échec conserve le fichier sélectionné pour réessayer.
4. **Verrouiller et effacer** : retire les références aux clés de la session et vide les champs de l'interface. Les téléchargements et le presse-papiers ne sont pas effacés. Une fermeture/recharge supprime également l'état de l'application. Une sortie avec une clé nouvellement générée sans téléchargement de sauvegarde demande confirmation si le navigateur le permet.

Le destinataire n'a pas à transmettre sa clé privée. L'application n'envoie pas elle-même les messages. Les espaces et les retours à la ligne sont conservés exactement. La taille maximale d'un texte clair est 2 Mio en UTF-8.

## Confidentialité et limites

- Les clés, phrases secrètes et messages sont traités uniquement par Web Crypto et JavaScript dans cet onglet. Aucun cookie, localStorage, sessionStorage, IndexedDB, service worker ou journal de contenu confidentiel.
- La politique CSP dans le document bloque les connexions (`connect-src 'none'`), les formulaires, objets et workers. Scripts/styles sont limités aux fichiers du même site. Il n'y a aucune ressource tierce.
- Sur un hébergement distant, le chargement initial communique les métadonnées habituelles (adresse IP, requête de page) à l'hébergeur. Aucun texte ou clé n'est mis dans l'URL ni envoyé. Le mode localhost avec connexion coupée évite ce contact avec un hébergeur distant.
- Un hébergeur compromis pourrait remplacer le code ou sa CSP. Le mode local avec une copie vérifiée offre un contrôle supplémentaire. Le navigateur, les extensions, le système et les éventuels outils de saisie doivent être dignes de confiance. Le code ne peut pas garantir un effacement physique de toute copie en mémoire gérée par JavaScript/navigateur.
- La copie vers le presse-papiers concerne seulement les messages chiffrés. L'enregistrement des fichiers est volontaire ; le dossier de téléchargement peut être synchronisé par votre système. La sauvegarde privée exportée reste chiffrée.
- Chaque message comporte une signature ECDSA vérifiable avec la clé publique de signature intégrée. Cela prouve que le message a été signé par le détenteur de la clé privée correspondante et qu'il n'a pas été modifié. La clé publique incluse ne prouve pas à elle seule le nom ou l'identité civile de l'expéditeur : comparez son empreinte à une identité reçue par un canal sûr. Il n'y a ni protection contre le rejeu ni confidentialité persistante en cas de compromission ultérieure de la clé RSA.
- L'enveloppe des messages est réencodée en Base64 URL-safe pour masquer sa structure JSON à première vue. Ce réencodage n'ajoute aucune protection cryptographique : les métadonnées restent accessibles à qui décode l'enveloppe, et la taille du message reste visible.
- Il s'agit d'un outil de chiffrement local, pas d'une messagerie auditée ou d'un protocole complet de communication de groupe.

## Formats et compatibilité

### Messages v3 signés et réencodés

L'enveloppe JSON `{v, alg, kid, iv, ek, ct, senderKid, senderKey, sig}` est encodée en UTF-8 puis en Base64 URL-safe sans padding. Aucun préfixe n'est ajouté. Le déchiffrement accepte uniquement ce format réencodé signé.

- `v: 3`, `alg: "RSA-OAEP-256+A256GCM+ECDSA-P256-SHA256"` ;
- RSA-OAEP avec SHA-256 encapsule une clé AES aléatoire de 256 bits par message ;
- AES-GCM utilise un nonce aléatoire de 96 bits et un tag de 128 bits ;
- `kid` identifie la clé publique RSA destinataire ; `senderKid` identifie la clé publique ECDSA signataire. Les deux sont les empreintes SHA-256 du SPKI DER, en hexadécimal minuscule groupé par quatre caractères ;
- `senderKey` contient la clé publique ECDSA SPKI et `sig` la signature ECDSA P-256 avec SHA-256 ; la signature couvre `v`, `alg`, `kid`, `iv`, `ek`, `ct`, `senderKid` et `senderKey` dans cet ordre ;
- les données authentifiées par AES-GCM sont l'encodage UTF-8 de `JSON.stringify({v:3, alg:"RSA-OAEP-256+A256GCM+ECDSA-P256-SHA256", kid})` dans cet ordre ;
- `iv`, `ek`, `ct`, `senderKey` et `sig` sont encodés en Base64 URL-safe sans padding. `ct` inclut le tag GCM ;
- la génération RSA utilise 3072 bits ; les imports acceptent RSA de 2048 à 8192 bits.

### Identité publique et sauvegarde privée v2

L'identité publique JSON contient la clé publique RSA PEM et la clé publique ECDSA SPKI encodée en Base64 URL-safe. Les clés privées ne sont pas incluses.

La sauvegarde privée JSON v2 chiffre ensemble les deux clés privées PKCS#8 avec PBKDF2-HMAC-SHA256 (600 000 itérations, sel aléatoire de 16 octets) et AES-256-GCM (nonce aléatoire de 12 octets). Les données authentifiées sont la chaîne UTF-8 `crypto-page/private-identity/v2/PBKDF2-SHA256/600000/A256GCM`.

Les clés privées ne sont exportées qu'au sein de cette sauvegarde chiffrée. L'interface et le moteur n'acceptent que la version JSON v2 générée par le bouton « Télécharger la clé privée » ; les versions antérieures et les PEM privés ne sont pas pris en charge.

### Limites d’import et compatibilité

- Les clés privées PEM, chiffrées ou non, et les sauvegardes privées JSON antérieures à la v2 sont refusées. Les clés publiques PEM peuvent toujours être importées pour chiffrer vers un destinataire.
- Les anciens messages ne sont pas pris en charge. Tous les correspondants doivent utiliser cette version pour lire les nouveaux messages.
- Les fichiers Python du dossier `crypto/` sont conservés comme référence historique. Ils ne sont jamais chargés ni exécutés par l'application.

## Vérifications

Node.js 22 ou supérieur, sans installation de dépendances pour les tests du moteur :

```sh
npm test
```

Le fichier `tests/keys-fixture.json` contient une **clé de test**, uniquement destinée à la suite de tests. Ne jamais l'utiliser pour de vrais échanges.

Pour les tests de navigateur, installer Playwright dans l'environnement de développement, installer Chromium, démarrer le serveur local, puis lancer :

```sh
npm install --no-save playwright
npx playwright install chromium
node tests/browser.cjs
```

Le parcours navigateur vérifie la génération, les imports/exports et le chiffrement/déchiffrement v3 signé et réencodé **réseau coupé**, la vérification de l'identité de signature, l'absence de nouvelles requêtes pendant ces opérations, l'absence de stockage persistant et le blocage des connexions par CSP. Il capture aussi les vues ordinateur et mobile dans `test-results/`.
