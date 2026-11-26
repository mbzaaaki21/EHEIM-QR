EHEIM - VERSION PREPAREE POUR HEBERGEMENT ET MOBILE

Commencer par lire :
1) DEPLOY_RAILWAY.md  -> héberger le serveur et conserver les données
2) MOBILE_SETUP.md    -> générer les applications Android et iOS

IMPORTANT :
- Ce paquet est volontairement sans .env, sans base de données réelle et sans photos privées.
- Garder l'archive originale comme sauvegarde locale privée.
- Ne jamais envoyer .env ou data/db.json sur GitHub.
- Le serveur doit être hébergé en HTTPS et le volume Railway doit être monté sur /app/data.
- Laisser ALLOWED_NETWORKS vide en hébergement cloud avec la version actuelle.
