# Déployer EHEIM en ligne avec Railway

Ce projet utilise actuellement Express + une base JSON locale (`data/db.json`). Pour conserver les comptes, présences, séances, photos et liaisons de téléphones après un redémarrage ou un nouveau déploiement, un volume persistant est obligatoire.

## Architecture retenue
- Railway héberge le serveur Node.js et fournit une adresse HTTPS.
- Un Railway Volume est monté exactement sur `/app/data`.
- Le serveur doit rester en une seule instance/réplica : la base JSON actuelle n'est pas conçue pour plusieurs instances simultanées.
- Ne pas configurer `ALLOWED_NETWORKS` avec les adresses Wi-Fi de l'école sur l'hébergement cloud : le serveur verra les adresses IP du réseau/du proxy cloud, pas les IP privées des téléphones. Laisser cette variable vide tant que le contrôle réseau n'a pas été repensé pour le cloud.

## A. Préparer un dépôt GitHub privé
1. Décompresser ce projet préparé.
2. Vérifier que `.env`, `data/db.json`, `data/photos/` et `node_modules/` ne sont pas présents.
3. Créer un dépôt GitHub **Private**.
4. Envoyer le contenu du dossier à GitHub. Le `.gitignore` et le `.dockerignore` excluent les données locales et les secrets.
5. Ne jamais ajouter `.env`, `data/db.json`, photos d'étudiants, mots de passe ou clés au dépôt.

## B. Créer le service Railway
1. Créer un projet Railway et choisir **Deploy from GitHub Repo**.
2. Sélectionner le dépôt privé EHEIM. Railway détectera le `Dockerfile` à la racine.
3. Dans le service, ouvrir **Settings → Networking → Generate Domain** pour obtenir un domaine public HTTPS.
4. Dans **Settings → Volumes**, ajouter un volume et définir exactement le **Mount Path** : `/app/data`.
5. Dans **Settings → Deploy**, garder une seule instance/réplica.
6. Dans **Variables**, ajouter :
   - `NODE_ENV` = `production`
   - `JWT_SECRET` = une nouvelle valeur aléatoire de 96 caractères hexadécimaux (voir commande ci-dessous)
   - `PROF_CODE` = un nouveau code professeur privé
   - `BASE_URL` = `https://VOTRE-DOMAINE-RAILWAY` (sans slash final)
   - `TRUST_PROXY` = `1`
   - `ALLOWED_NETWORKS` = laisser vide
   - `QR_GRACE_MS` = `5000`
7. Générer/redéployer le service après avoir renseigné les variables.

Pour générer un secret localement dans le terminal de VS Code :

```powershell
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Ne réutilisez pas le secret JWT ni le code professeur contenus dans l'ancien `.env`. Le fichier `.env` transmis avec l'archive originale doit rester privé ; faites une rotation des secrets avant la mise en production.

## C. Vérifier le déploiement
Ouvrir `https://VOTRE-DOMAINE-RAILWAY/health`. La réponse attendue est :

```json
{"ok":true,"service":"eheim"}
```

Puis ouvrir la racine du domaine et tester : connexion professeur, connexion étudiant, création de séance, QR dynamique, scan caméra, historique et export Excel.

## D. Transférer les données locales (optionnel, à faire avec prudence)
Le ZIP original contenait une base locale avec des comptes, des présences et des événements de sécurité. Le paquet préparé ici ne l'embarque volontairement pas.

1. Faire une copie de sauvegarde de l'ancien dossier `data` et conserver l'original hors ligne.
2. Arrêter l'ancien serveur local avant la copie pour éviter une écriture pendant l'export.
3. Dans Railway, ouvrir le volume et utiliser l'outil de navigation du volume (`railway volume browse /`) pour téléverser l'ancien `data/db.json` à la racine du volume (il apparaîtra dans le conteneur comme `/app/data/db.json`).
4. Téléverser aussi le contenu de `data/photos/` dans le dossier `photos` du volume, si des photos existent.
5. Redémarrer le service et vérifier les comptes et les historiques avant de supprimer toute sauvegarde locale.

Important : ne téléversez jamais `data/db.json` ou les photos dans GitHub. Ce fichier contient des informations personnelles. Si vous préférez repartir de zéro, laissez le volume vide : `db.js` créera une base vide au premier démarrage.

## E. Sauvegardes
Avant toute mise à jour importante, sauvegarder le volume (au minimum `db.json` et `photos/`). Une base JSON sur volume convient à un petit déploiement mono-instance. Pour plusieurs instances, une forte charge ou une disponibilité critique, migrer vers PostgreSQL avec une stratégie de sauvegarde testée.
