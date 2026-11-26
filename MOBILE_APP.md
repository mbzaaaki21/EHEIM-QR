# EHEIM — application mobile

Les instructions adaptées à cette version du projet sont dans **MOBILE_SETUP.md**.
Pour héberger le serveur avec stockage persistant et HTTPS, suivre d’abord **DEPLOY_RAILWAY.md**.

Le site utilise actuellement Express et une base JSON locale. Il faut donc un hébergement Node.js avec un volume persistant monté sur `/app/data`, une seule instance du serveur et une URL HTTPS configurée dans `BASE_URL`.
