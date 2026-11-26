# EHEIM QR Attendance — Gestion des classes et des absences

## Mise à jour d'un projet existant
Remplacer les fichiers source fournis (`server.js`, `db.js`, `public/index.html`) dans le projet existant. **Conserver impérativement le fichier `data/db.json` actuel et le fichier `.env` actuel** : ils contiennent les comptes, séances, présences et secrets de l'installation. La nouvelle propriété `classes` est initialisée automatiquement sans effacer les données existantes.

## Installation neuve
1. Installer Node.js 18 ou supérieur.
2. Dans le dossier du projet : `npm install`
3. Copier `.env.example` vers `.env`, puis définir un `JWT_SECRET` long et privé ainsi que le `PROF_CODE`.
4. Lancer : `npm start`
5. Ouvrir `http://localhost:3000`.

## Importation des listes
Dans le tableau de bord professeur, ouvrir **Mes listes de classes** et importer un fichier `.xlsx`.
La première ligne doit contenir les en-têtes `Matricule`, `Nom` et éventuellement `Prénom` (les accents et majuscules sont acceptés).
Une nouvelle importation avec le même nom de classe remplace sa liste courante. Les anciennes séances gardent une copie de la liste au moment où elles ont été créées.

## Matricules (format F0000)
Un étudiant s'inscrit avec un matricule au format **F0000** (la lettre F suivie de 4 chiffres, ex. `F5555`). Le format est vérifié à l'inscription et la lettre est enregistrée en majuscule. Chaque matricule est unique : deux élèves ne peuvent pas partager le même.
La classe **CPI 1** intégrée (`CPI1_TEST_STUDENTS` dans `server.js`) contient les 24 élèves réels. Les matricules `F0001` à `F0024` sont **provisoires** (Ahmed Laazibi garde `F5555`) : remplacez-les dans `server.js` par les vrais matricules, ou importez un fichier Excel.

## Séances et QR Code
Choisir une classe et une matière avant de créer une séance. Le QR Code existant est conservé.
Un étudiant n'est accepté que si son matricule est présent dans la liste figée de la séance. Les doublons de scan sont refusés.
À la clôture (ou à l'expiration) de la séance, les étudiants sans scan sont comptés comme absents dans le rapport Excel.

## Rapports
Le rapport Excel contient tous les élèves, leur matricule, statut et heure de scan, ainsi que le total, les présents, les absents, la date, le professeur, la matière et la classe.
Les présents sont en vert et les absents en rouge. L'historique des séances reste conservé.

## Stockage et sécurité
Les listes sont stockées dans `data/db.json`, séparées par `professorId`. Toutes les routes de gestion de classes et de séances vérifient la session professeur et la propriété de la ressource.
Le projet utilise actuellement une base JSON locale, comme dans la version fournie. Pour un déploiement multi-instance ou une utilisation à grande échelle, migrer vers une base transactionnelle est recommandé.

## Sécurité (ajouts)
- `JWT_SECRET` (32 caractères minimum) et `PROF_CODE` sont **obligatoires** : le serveur refuse de démarrer sans eux.
- Avec `BASE_URL` en `https://`, le cookie de session passe en `secure` et HSTS est activé. Derrière un proxy, ajouter `TRUST_PROXY=1`.
- Limitation des tentatives : connexion (8 échecs / 15 min par email+IP), inscription (15 échecs / h par IP), code de séance (10 échecs / 10 min par étudiant).
- Mot de passe : 8 caractères minimum. Un matricule ne peut être utilisé que par un seul compte étudiant.
- En-têtes de sécurité (CSP, anti-clickjacking, nosniff). Un professeur ne voit que les photos de ses propres étudiants.

---

# Mise à jour sécurité : QR dynamique + liaison étudiant ↔ téléphone

## Fichiers livrés
| Fichier | Statut |
|---|---|
| `server.js` | **modifié** (routes existantes conservées) |
| `public/index.html` | **modifié** (design et `style.css` inchangés ; styles ajoutés en `<style>` local) |
| `lib/security.js`, `lib/devices.js` | **nouveaux** (aucune nouvelle dépendance npm) |
| `scripts/create-admin.js` | **nouveau** (création d'un compte administrateur) |
| `test/security.test.js` | **nouveau** (tests automatiques) |

`db.js`, `data/db.json`, `.env`, `package.json` et `style.css` ne sont **pas** touchés : copiez simplement les fichiers ci-dessus dans votre projet. Les nouvelles collections (`devices`, `deviceRequests`, `deviceChanges`, `auditLog`, `securityLog`) sont créées automatiquement dans `data/db.json`, comme `classes` auparavant. Comptes, séances et présences existants sont conservés.

## Installation (PowerShell, dans VS Code)
```powershell
cd "C:\chemin\vers\EHEIM_QR_Attendance"
# 1. Copier les fichiers livrés dans le projet (en conservant data\db.json et .env)
npm install                      # aucune nouvelle dépendance ; sert seulement si node_modules est absent
node --test test/security.test.js   # tests automatiques (9 tests)
npm start
```
Variables `.env` facultatives :
```
ALLOWED_NETWORKS=Wi-Fi EHEIM=192.168.1.0/24,Wi-Fi Admin=10.0.0.0/8   # réseaux autorisés, nom facultatif devant « = » (vide = pas de restriction)
QR_GRACE_MS=5000                              # tolérance réseau après les 30 s (0 à 30000)
```
Compte administrateur (serveur arrêté) :
```powershell
node scripts/create-admin.js "Nom Complet" admin@ecole.ma "MotDePasseLong"
```

## Fonctionnement
**QR dynamique.** Le serveur signe (HMAC-SHA-256) un jeton `séance.créneau.signature` renouvelé toutes les 30 s. Un jeton est refusé s'il est falsifié, d'une autre séance, ou plus ancien que 30 s + `QR_GRACE_MS`. L'ancien QR statique est refusé. Le code de secours à 6 caractères tourne aussi toutes les 30 s. Le compte à rebours du navigateur n'est qu'un affichage : le serveur revérifie à chaque scan. Bouton **Mode projecteur** (plein écran) pour le QR et le code.

**Liaison d'appareil.** À la première connexion, un identifiant aléatoire (32 octets, `crypto`) est placé dans le cookie `eheim_device` (HttpOnly, SameSite=Strict, Secure en HTTPS). Seul son SHA-256 est stocké. Vérifié à chaque connexion et à chaque scan. Le cookie survit à la déconnexion : un téléphone lié à un étudiant ne peut pas ouvrir le compte d'un autre.
Autre téléphone ou cookies supprimés → connexion possible mais **présence bloquée** + demande de changement créée automatiquement. Un professeur ou administrateur l'approuve (l'ancien téléphone est révoqué immédiatement) ou la refuse (l'étudiant peut renvoyer une demande après 10 min).

**Gestion des appareils** (onglet professeur/admin) : appareils associés, demandes, bloquer/débloquer, historique des changements, journal d'audit et événements de sécurité, recherche nom/prénom/matricule, confirmation avant chaque action (aussi exigée côté serveur).

**Protections :** compte + téléphone + jeton + horodatage serveur + doublons refusés ; limitation des tentatives (par étudiant et par IP) ; restriction Wi-Fi par IP ; événement `SUSPICIOUS_ATTEMPTS` après 5 refus en 10 min ; CSRF (contrôle d'origine + jeton lié à la session sur toute requête modifiante) ; chaque présence est signée (HMAC) pour détecter une modification manuelle de `db.json` (onglet Statistiques).

Corrections au passage : deux inscriptions simultanées avec le même matricule pouvaient toutes deux passer (hachage bcrypt asynchrone) ; les jetons de séance ne sont plus envoyés au navigateur.

## Limites à connaître
- Un cookie ne prouve pas la présence physique : un étudiant sans téléphone encore lié peut lier le téléphone d'un camarade en navigation privée (première association automatique). Mitigation : consulter le journal et lier les appareils en début d'année sous surveillance.
- Une photo du QR transmise en moins de ~35 s depuis un téléphone **autorisé** reste possible ; le Wi-Fi restreint et les 30 s réduisent ce risque sans l'éliminer.
- Restriction Wi-Fi : fiable si le serveur voit les IP locales (même réseau). En hébergement distant, `ALLOWED_NETWORKS` doit contenir l'IP publique de l'établissement et `TRUST_PROXY` doit être défini.
- Base JSON : sur un seul processus Node, chaque vérification + écriture est synchrone donc sans course. Les risques restent un second processus ou une coupure pendant l'écriture. Pour une utilisation à grande échelle, migrer vers SQLite/PostgreSQL ; je n'ai pas migré car `db.js` n'était pas dans l'archive.

## Tests de sécurité manuels
1. Scanner le QR, attendre 40 s, ouvrir le lien → « QR Code expiré ».
2. Valider deux fois → « Présence déjà enregistrée ».
3. Se déconnecter, se connecter avec le compte d'un camarade sur le même téléphone → refusé.
4. Se connecter depuis un autre navigateur ou en navigation privée → présence bloquée, demande visible côté professeur.
5. Approuver → le nouveau téléphone fonctionne, l'ancien est refusé immédiatement.
6. Avec `ALLOWED_NETWORKS` réglé sur un autre réseau → « Connectez-vous au Wi-Fi de l'établissement ».
7. Taper 5 codes faux → événement `SUSPICIOUS_ATTEMPTS` dans le journal.

**Session étudiant :** une fois inscrit ou connecté, l'étudiant reste connecté 180 jours sur son téléphone : en scannant le QR, il entre directement dans son compte et la présence est validée sans ressaisir email et mot de passe (professeurs : 7 jours).

**Réseau des appareils :** dans « Appareils associés », deux colonnes montrent l'adresse IP de la dernière connexion et du dernier scan, le nom du réseau (celui donné dans `ALLOWED_NETWORKS`) et si elle est dans le Wi-Fi de l'établissement. Un navigateur ne révèle jamais le nom (SSID) du Wi-Fi : le serveur ne connaît que l'IP, d'où ce nom associé à une plage d'adresses.

## Application mobile (Android / iOS)
Le site est installable comme application (PWA) et contient un scanner de QR Code intégré. Voir `MOBILE_APP.md` (HTTPS obligatoire, installation PWA, génération d'APK/IPA avec Capacitor, précautions sur la liaison d'appareil).
