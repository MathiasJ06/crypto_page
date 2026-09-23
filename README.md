# Crypto · Chiffrement local

Une page statique en français pour chiffrer et déchiffrer des messages sur votre appareil. Aucun compte, serveur de traitement, Pyodide, CDN, télémétrie ou dépendance JavaScript de production.

## Ouvrir depuis GitHub Pages

Adresse du site : **https://mathiasj06.github.io/crypto_page/**.

GitHub Pages est déjà activé sur le dépôt. Pour remplacer l'ancienne application, publier `index.html`, `style.css`, `script.js` et `crypto-engine.js` à la racine de la branche utilisée par Pages. Le fichier `.nojekyll` permet de servir les fichiers statiques directement. Si la source doit être configurée : **Settings → Pages → Build and deployment → Deploy from a branch → main → / (root)**.

Aucun serveur Python n'est nécessaire pour les visiteurs. GitHub fournit les fichiers statiques, puis le navigateur réalise toutes les opérations sensibles localement. La publication n'ajoute aucun appel réseau à l'application.

Les changements sont préparés pour publication ; le site public reste sur l'ancienne version tant que les nouveaux fichiers n'ont pas été envoyés au dépôt et déployés.

## Démarrer localement (facultatif)

Servez ce dossier avec un serveur statique. Python sert uniquement les fichiers ; il ne traite pas les clés ni les messages :

```sh
python3 -m http.server 8000 --bind 127.0.0.1
```

Ouvrez **http://localhost:8000**. N'utilisez pas l'ouverture directe `file://` : les modules JavaScript peuvent être bloqués. Un hébergement statique HTTPS (dont GitHub Pages) convient aussi ; HTTP distant n'active pas Web Crypto.

Une fois la page chargée, elle fonctionne sans connexion réseau. L'interface télécharge seulement `index.html`, `style.css`, `script.js` et `crypto-engine.js` au démarrage. Elle n'effectue aucune requête lors de la saisie, génération, importation, sauvegarde, encryption ou décryption. Les téléchargements sont des fichiers Blob créés localement.

## Utilisation

1. **Mes clés** : générez votre paire RSA. Téléchargez la clé publique à partager et la sauvegarde privée protégée par une phrase secrète longue et unique (12 caractères minimum). Vérifiez que la sauvegarde est bien enregistrée. La phrase n'est pas récupérable par un service.
2. **Chiffrer** : importez la clé publique de votre destinataire. Comparez l'empreinte complète avec lui par un autre canal. Saisissez le message, chiffrez, puis copiez ou téléchargez uniquement le résultat chiffré pour le transmettre.
3. **Déchiffrer** : sélectionnez votre sauvegarde privée dans « Mes clés », saisissez sa phrase, puis cliquez sur « Importer ma clé privée ». Collez/importez ensuite le message reçu et déchiffrez. Un échec conserve le fichier sélectionné pour réessayer.
4. **Verrouiller et effacer** : retire les références aux clés de la session et vide les champs de l'interface. Les téléchargements et le presse-papiers ne sont pas effacés. Une fermeture/recharge supprime également l'état de l'application. Une sortie avec une clé nouvellement générée sans téléchargement de sauvegarde demande confirmation si le navigateur le permet.

Le destinataire n'a pas à transmettre sa clé privée. L'application n'envoie pas elle-même les messages. Les espaces et les retours à la ligne sont conservés exactement. La taille maximale d'un texte clair est 2 Mio en UTF-8.

## Confidentialité et limites

- Les clés, phrases secrètes et messages sont traités uniquement par Web Crypto et JavaScript dans cet onglet. Aucun cookie, localStorage, sessionStorage, IndexedDB, service worker ou journal de contenu confidentiel.
- La politique CSP dans le document bloque les connexions (`connect-src 'none'`), les formulaires, objets et workers. Scripts/styles sont limités aux fichiers du même site. Il n'y a aucune ressource tierce.
- Sur un hébergement distant, le chargement initial communique les métadonnées habituelles (adresse IP, requête de page) à l'hébergeur. Aucun texte ou clé n'est mis dans l'URL ni envoyé. Le mode localhost avec connexion coupée évite ce contact avec un hébergeur distant.
- Un hébergeur compromis pourrait remplacer le code ou sa CSP. Le mode local avec une copie vérifiée offre un contrôle supplémentaire. Le navigateur, les extensions, le système et les éventuels outils de saisie doivent être dignes de confiance. Le code ne peut pas garantir un effacement physique de toute copie en mémoire gérée par JavaScript/navigateur.
- La copie vers le presse-papiers concerne seulement les messages chiffrés. L'enregistrement des fichiers est volontaire ; le dossier de téléchargement peut être synchronisé par votre système. La sauvegarde privée exportée reste chiffrée.
- Le chiffrement protège le message et détecte ses modifications, mais **n'authentifie pas l'expéditeur**. Toute personne ayant la clé publique peut créer un message pour son détenteur. Pas de signature d'expéditeur, de protection contre le rejeu ni de confidentialité persistante en cas de compromission ultérieure de la clé RSA.
- L'empreinte de la clé destinataire est visible dans les messages v2 ; elle sert d'identifiant de clé et peut relier plusieurs échanges. Le format ne promet pas l'anonymat ni la dissimulation des métadonnées.
- Il s'agit d'un outil de chiffrement local, pas d'une messagerie auditée ou d'un protocole complet de communication de groupe.

## Formats et compatibilité

### Messages v2

Enveloppe JSON `{v, alg, kid, iv, ek, ct}` :

- `v: 2`, `alg: "RSA-OAEP-256+A256GCM"` ;
- RSA-OAEP avec SHA-256 encapsule une clé AES aléatoire de 256 bits par message ;
- AES-GCM utilise un nonce aléatoire de 96 bits et un tag de 128 bits ;
- `kid` est l'empreinte SHA-256 du SPKI DER, en hexadécimal minuscule groupé par quatre caractères ;
- les données authentifiées sont l'encodage UTF-8 de `JSON.stringify({v:2, alg:"RSA-OAEP-256+A256GCM", kid})` dans cet ordre ;
- `iv`, `ek` et `ct` sont encodés en Base64 URL-safe sans padding. `ct` inclut le tag GCM ;
- la génération RSA utilise 3072 bits ; les imports acceptent RSA de 2048 à 8192 bits.

### Sauvegardes privées v1

Format JSON propre à cette application, et non PEM PKCS#8 chiffré standard : PBKDF2-HMAC-SHA256 (600 000 itérations, sel aléatoire de 16 octets) dérive une clé AES-256-GCM. Nonce aléatoire de 12 octets. Le contenu protégé est le PKCS#8 DER. Les données authentifiées sont la chaîne UTF-8 `crypto-page/private-key/v1/PBKDF2-SHA256/600000/A256GCM`. Les paramètres importés sont strictement bornés et validés.

Les clés privées sont exportables en mémoire afin de permettre leur sauvegarde ; aucun export privé non chiffré n'est proposé dans l'interface.

### Ancienne version

- Import des anciennes clés publiques SPKI PEM et privées PKCS#8 PEM **non chiffrées** (`.pem`, `.key` ou `.txt`). La clé publique est dérivée automatiquement de la clé privée importée.
- Lecture des anciennes enveloppes RSA-OAEP/SHA-256 + Fernet : HMAC-SHA256 vérifié avant déchiffrement AES-128-CBC. Pas d'expiration temporelle ajoutée à l'ancien format.
- Les nouveaux messages v2 ne peuvent pas être lus par l'ancienne interface. Tous les correspondants doivent utiliser cette version pour recevoir de nouveaux messages.
- Les fichiers Python du dossier `crypto/` sont conservés comme référence historique. Ils ne sont jamais chargés ni exécutés par l'application.

## Vérifications

Node.js 22 ou supérieur, sans installation de dépendances pour les tests du moteur :

```sh
npm test
```

Le fichier `tests/legacy-fixture.json` contient une **clé de test publique**, générée uniquement pour tester la compatibilité avec l'ancien Python. Ne jamais l'utiliser pour de vrais échanges.

Pour les tests de navigateur, installer Playwright dans l'environnement de développement, installer Chromium, démarrer le serveur local, puis lancer :

```sh
npm install --no-save playwright
npx playwright install chromium
node tests/browser.cjs
```

Le parcours navigateur vérifie la génération, les imports/exports, le chiffrement v2 et la lecture de Fernet **réseau coupé**, l'absence de nouvelles requêtes pendant ces opérations, l'absence de stockage persistant et le blocage des connexions par CSP. Il capture aussi les vues ordinateur et mobile dans `test-results/`.
