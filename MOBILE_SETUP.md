# Créer les applications Android et iOS EHEIM avec Capacitor

Le wrapper mobile charge le site EHEIM hébergé en HTTPS. Les API, sessions, QR dynamiques et comptes restent gérés par le serveur en ligne. Le navigateur intégré de l'application possède son propre stockage/cookie : chaque étudiant doit se connecter une première fois dans l'application qu'il utilisera ensuite. Le scanner doit être lancé avec le bouton intégré à EHEIM, pas avec l'appareil photo externe.

## 1. Après l'hébergement
Remplacer `https://REMPLACER-PAR-LE-DOMAINE-EHEIM` dans `capacitor.config.json` par le domaine HTTPS exact généré pour EHEIM, par exemple `https://eheim-production.up.railway.app`.

## 2. Installer Capacitor (PowerShell dans le dossier du projet)
```powershell
npm install @capacitor/core @capacitor/cli @capacitor/android @capacitor/ios
npx cap add android
npx cap sync android
npx cap open android
```

Dans Android Studio :
1. Laisser Gradle terminer la synchronisation.
2. Tester sur un vrai téléphone Android avec caméra.
3. Pour produire un APK signé : **Build → Generate Signed Bundle / APK → APK**.
4. Conserver le keystore et ses mots de passe dans un endroit sûr ; sans eux, les mises à jour de la même application peuvent être compliquées.

### Autorisation caméra Android
Dans `android/app/src/main/AndroidManifest.xml`, ajouter avant la balise `<application>` si elle n'existe pas déjà :
```xml
<uses-permission android:name="android.permission.CAMERA" />
<uses-feature android:name="android.hardware.camera" android:required="false" />
```
Le scanner utilise `navigator.mediaDevices.getUserMedia`. Tester l'autorisation caméra sur un appareil physique ; les permissions du WebView peuvent nécessiter un ajustement natif selon la version Android.

## 3. Créer la version iOS (Mac obligatoire)
Sur un Mac avec Xcode installé, dans le même projet :
```bash
npm install @capacitor/core @capacitor/cli @capacitor/android @capacitor/ios
npx cap add ios
npx cap sync ios
npx cap open ios
```
Dans `ios/App/App/Info.plist`, ajouter la description d'usage caméra :
```xml
<key>NSCameraUsageDescription</key>
<string>La caméra est utilisée pour scanner le QR Code de présence EHEIM.</string>
```
Tester sur un iPhone réel dans Xcode. Pour distribution publique, utiliser App Store Connect/TestFlight et vérifier les exigences Apple. Un Mac/Xcode est nécessaire pour signer et compiler iOS ; Windows seul ne suffit pas.

## 4. Après chaque modification du site
Le site est chargé depuis le serveur HTTPS distant : les changements web sont donc publiés sur le serveur et visibles sans reconstruire l'application. Si vous modifiez la configuration native ou ajoutez un plugin Capacitor, exécuter `npx cap sync` puis reconstruire l'application.

## 5. Point de sécurité essentiel : téléphone lié au compte étudiant
- Le navigateur et l'application native ont des cookies de stockage distincts.
- Chaque étudiant doit se connecter dans l'application native la première fois.
- Scanner le QR depuis le bouton de l'application conserve le contexte de connexion de l'application.
- Une désinstallation/réinstallation ou un effacement des données peut créer une nouvelle identité d'appareil et déclencher le processus d'approbation prévu par EHEIM.

## 6. Limite Apple
Une application qui ne fait qu'afficher un site peut être refusée par Apple si elle n'apporte pas suffisamment de fonctionnalités natives. Tester la distribution TestFlight et consulter les règles App Store avant de payer ou de lancer une publication publique. La PWA reste une solution de repli simple : Android Chrome → Installer ; iPhone Safari → Partager → Sur l'écran d'accueil.
