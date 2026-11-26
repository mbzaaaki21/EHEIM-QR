require('dotenv').config();
const express = require('express');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const QRCode = require('qrcode');
const ExcelJS = require('exceljs');
const db = require('./db');
const sec = require('./lib/security');
const { makeDevices } = require('./lib/devices');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;
const PROF_CODE = process.env.PROF_CODE;
// Sécurité : le serveur refuse de démarrer sans vrais secrets (voir .env.example)
if (!SECRET || SECRET.length < 32 || /changez/i.test(SECRET) || !PROF_CODE || /changez/i.test(PROF_CODE)) {
  console.error('ERREUR : définissez dans .env un JWT_SECRET (32 caractères minimum, aléatoire) et un PROF_CODE personnel.');
  console.error('Générer un secret :  node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
  process.exit(1);
}

function lanIp() {
  for (const list of Object.values(os.networkInterfaces()))
    for (const i of list) if (i.family === 'IPv4' && !i.internal) return i.address;
  return 'localhost';
}
// QR dynamique (30 s) + tolérance réseau, réseau Wi-Fi autorisé (facultatif)
const qr = sec.makeQr(SECRET, { graceMs: Math.min(Math.max(parseInt(process.env.QR_GRACE_MS) || 5000, 0), 30000) });
let NETWORKS;
try { NETWORKS = sec.parseNetworks(process.env.ALLOWED_NETWORKS); } catch (e) { console.error('ERREUR ALLOWED_NETWORKS :', e.message); process.exit(1); }
const BASE_URL = (process.env.BASE_URL || `http://${lanIp()}:${PORT}`).replace(/\/$/, '');

const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || 1); // derrière Nginx/Caddy/hébergeur
const HTTPS = BASE_URL.startsWith('https://');
const dev = makeDevices({ db, uid: () => crypto.randomBytes(8).toString('hex'), https: HTTPS });
// En-têtes de sécurité (équivalent allégé de helmet)
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-ancestors 'none'",
  ].join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(), geolocation=()');
  if (HTTPS) res.setHeader('Strict-Transport-Security', 'max-age=15552000');
  next();
});
// Limiteur de tentatives (en mémoire) : bloque après `max` échecs dans la fenêtre
function limiter({ windowMs, max, key, message }) {
  const hits = new Map();
  setInterval(() => { const t = Date.now(); for (const [k, v] of hits) if (v.reset < t) hits.delete(k); }, 60000).unref();
  return (req, res, next) => {
    const k = key(req), now = Date.now();
    let h = hits.get(k);
    if (!h || h.reset < now) { h = { n: 0, reset: now + windowMs }; hits.set(k, h); }
    if (h.n >= max) {
      res.setHeader('Retry-After', Math.ceil((h.reset - now) / 1000));
      return res.status(429).json({ error: message || 'Trop de tentatives, réessayez plus tard' });
    }
    res.on('finish', () => { if (res.statusCode >= 400 && res.statusCode !== 429) h.n++; });
    next();
  };
}
const loginLimit = limiter({ windowMs: 15 * 60000, max: 8, key: (r) => r.ip + '|' + String((r.body && r.body.email) || '').toLowerCase(), message: 'Trop d’échecs de connexion, réessayez dans 15 minutes' });
const registerLimit = limiter({ windowMs: 60 * 60000, max: 15, key: (r) => r.ip, message: 'Trop de tentatives d’inscription, réessayez plus tard' });
const checkinLimit = limiter({ windowMs: 10 * 60000, max: 10, key: (r) => r.user.id, message: 'Trop de codes invalides, patientez quelques minutes' });
const scanIpLimit = limiter({ windowMs: 10 * 60000, max: 80, key: (r) => r.ip, message: 'Trop de tentatives depuis ce réseau, patientez quelques minutes' });
const deviceReqLimit = limiter({ windowMs: 60 * 60000, max: 6, key: (r) => r.user.id, message: 'Trop de demandes, réessayez plus tard' });
// Protection CSRF (1/2) : toute requête modifiante doit provenir de notre propre origine
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const host = (process.env.TRUST_PROXY && req.headers['x-forwarded-host']) || req.headers.host;
  const origin = req.headers.origin;
  if (origin) { let h = ''; try { h = new URL(origin).host; } catch {} if (h !== host) return res.status(403).json({ error: 'Origine de la requête refusée' }); }
  else if (req.headers['sec-fetch-site'] && !['same-origin', 'none'].includes(req.headers['sec-fetch-site'])) return res.status(403).json({ error: 'Origine de la requête refusée' });
  next();
});
app.use('/api', (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
app.use(express.json({ limit: '8mb' }));
app.use(cookieParser());
// Endpoint de santé pour l'hébergeur (aucune donnée personnelle exposée).
app.get('/health', (req, res) => res.status(200).json({ ok: true, service: 'eheim' }));
app.use(express.static(path.join(__dirname, 'public')));

const uid = () => crypto.randomBytes(8).toString('hex');
const isActive = (s) => !s.closed && Date.now() < s.expiresAt;
const safeUser = (u) => ({
  id: u.id, name: u.name, email: u.email, role: u.role, matricule: u.matricule,
  photo: u.photoAt ? `/api/users/${u.id}/photo?v=${u.photoAt}` : '',
});

// ---------- Photos (stockées dans data/photos, hors du dossier public) ----------
const PHOTO_DIR = path.join(__dirname, 'data', 'photos');
fs.mkdirSync(PHOTO_DIR, { recursive: true });
const photoFile = (id) => path.join(PHOTO_DIR, id + '.jpg');
// Reçoit une image JPEG en "data URL" (redimensionnée par le navigateur), la vérifie et l'enregistre
function savePhoto(user, dataUrl) {
  const prefix = 'data:image/jpeg;base64,';
  if (typeof dataUrl !== 'string' || !dataUrl.startsWith(prefix)) return false;
  const buf = Buffer.from(dataUrl.slice(prefix.length), 'base64');
  if (buf.length < 100 || buf.length > 300 * 1024) return false;
  if (buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) return false; // signature JPEG
  fs.writeFileSync(photoFile(user.id), buf);
  user.photoAt = Date.now();
  return true;
}

// ---------- Auth ----------
const STAFF = ['professor', 'admin'];
// Jeton CSRF lié à la session (HMAC) : renvoyé dans le corps JSON, jamais dans un cookie lisible par un autre site
const csrfFor = (userId, iat) => sec.hmac(SECRET, `csrf|${userId}|${iat}`).toString('base64url');
function auth(role) {
  return (req, res, next) => {
    let payload, user;
    try {
      payload = jwt.verify(req.cookies.token, SECRET);
      user = db.data.users.find((u) => u.id === payload.id);
      if (!user) throw new Error();
    } catch { return res.status(401).json({ error: 'Non connecté' }); }
    if (role === 'staff' ? !STAFF.includes(user.role) : role && user.role !== role) return res.status(403).json({ error: 'Accès refusé' });
    if (!['GET', 'HEAD'].includes(req.method) && !sec.safeEq(req.get('x-csrf-token') || '', csrfFor(user.id, payload.iat)))
      return res.status(403).json({ error: 'Session de sécurité expirée, rechargez la page' });
    req.user = user; req.csrf = csrfFor(user.id, payload.iat);
    next();
  };
}
function setCookie(res, user) {
  // Étudiant déjà inscrit : il reste connecté 180 jours sur son téléphone et entre directement dans son compte
  const days = user.role === 'student' ? 180 : 7;
  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: days + 'd' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: HTTPS, maxAge: days * 864e5 });
  return csrfFor(user.id, jwt.decode(token).iat);
}
const deviceState = (req, res, user) => {
  if (user.role !== 'student') return null;
  const ev = dev.evaluate(req, res, user);
  if (ev.changed) db.save();                      // on n'écrit le fichier que si quelque chose a changé
  return dev.view.status(ev);
};

app.post('/api/register', registerLimit, async (req, res) => {
  const { name, email, password, role, matricule, profCode, photo } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Champs obligatoires manquants' });
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Mot de passe : 8 caractères minimum' });
  if (!['student', 'professor'].includes(role)) return res.status(400).json({ error: 'Rôle invalide' });
  if (role === 'student' && !/^F\d{4}$/i.test(String(matricule || '').trim())) return res.status(400).json({ error: 'Matricule obligatoire au format F0000 (ex. : F5555)' });
  const matriculeStd = role === 'student' ? String(matricule).trim().toUpperCase() : '';
  if (role === 'professor' && profCode !== PROF_CODE) return res.status(403).json({ error: 'Code professeur incorrect' });
  if (role === 'student' && db.data.users.some((u) => u.role === 'student' && normMat(u.matricule) === normMat(matriculeStd))) return res.status(409).json({ error: 'Ce matricule est déjà utilisé par un autre compte' });
  const mail = String(email).trim().toLowerCase();
  if (typeof name !== 'string' || name.trim().length < 2 || name.length > 100 || !/^\S+@\S+\.\S+$/.test(mail) || mail.length > 150) return res.status(400).json({ error: 'Nom ou adresse e-mail invalide' });
  if (db.data.users.some((u) => u.email === mail)) return res.status(409).json({ error: 'Email déjà utilisé' });
  // Un téléphone déjà associé à un autre étudiant ne peut pas créer un second compte
  if (role === 'student') {
    const probe = { id: '_new', name: name.trim(), email: mail, role, matricule: matriculeStd };
    const raw = req.cookies[dev.COOKIE], known = raw && db.data.devices.find((d) => d.hash === sec.hashDevice(raw));
    if (known && known.status !== 'revoked') { dev.sec('DEVICE_CONFLICT', probe, 'Inscription refusée : téléphone déjà associé à un autre compte', req.ip); db.save(); return res.status(403).json({ error: 'Ce téléphone est déjà associé à un autre compte étudiant', code: 'DEVICE_CONFLICT' }); }
  }
  const user = {
    id: uid(), name: name.trim(), email: mail, role,
    matricule: matriculeStd,
    password: await bcrypt.hash(password, 10), createdAt: Date.now(),
  };
  if (role === 'student' && photo) savePhoto(user, photo); // photo facultative à l'inscription
  // Revérification juste avant l'écriture : le hachage bcrypt est asynchrone, deux inscriptions simultanées ne doivent pas passer
  if (db.data.users.some((u) => u.email === mail || (role === 'student' && u.role === 'student' && normMat(u.matricule) === normMat(matriculeStd))))
    return res.status(409).json({ error: 'Email ou matricule déjà utilisé' });
  db.data.users.push(user);
  const csrf = setCookie(res, user);
  const device = deviceState(req, res, user);
  db.save();
  res.json({ user: safeUser(user), csrf, device });
});

app.post('/api/login', loginLimit, async (req, res) => {
  const { email, password } = req.body || {};
  const user = db.data.users.find((u) => u.email === String(email || '').trim().toLowerCase());
  if (!user || !(await bcrypt.compare(password || '', user.password)))
    return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  if (user.role === 'student') {
    const ev = dev.evaluate(req, res, user);
    if (ev.state === 'conflict') {            // ce téléphone appartient à un autre étudiant : aucune session n'est ouverte
      dev.sec('DEVICE_CONFLICT', user, 'Connexion refusée : téléphone associé à un autre compte', req.ip); db.save();
      return res.status(403).json({ error: 'Ce téléphone est associé à un autre compte étudiant. Utilisez votre propre téléphone.', code: 'DEVICE_CONFLICT' });
    }
    const csrf = setCookie(res, user); if (ev.changed) db.save();
    return res.json({ user: safeUser(user), csrf, device: dev.view.status(ev) });
  }
  const csrf = setCookie(res, user);
  res.json({ user: safeUser(user), csrf, pendingDeviceRequests: dev.view.pendingCount() });
});

// Le cookie de liaison d'appareil (eheim_device) est volontairement conservé à la déconnexion
app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/me', auth(), (req, res) => {
  const device = deviceState(req, res, req.user);
  res.json({ user: safeUser(req.user), csrf: req.csrf, device, pendingDeviceRequests: STAFF.includes(req.user.role) ? dev.view.pendingCount() : undefined });
});
app.get('/api/device/status', auth('student'), (req, res) => res.json({ device: deviceState(req, res, req.user) }));
app.post('/api/device/request', auth('student'), deviceReqLimit, (req, res) => {
  const st = dev.reRequest(req, res, req.user); db.save();
  if (st.state === 'conflict') return res.status(403).json({ error: 'Ce téléphone est associé à un autre compte', code: 'DEVICE_CONFLICT' });
  if (st.wait) return res.status(429).json({ error: 'Patientez quelques minutes avant de renvoyer une demande' });
  res.json({ device: dev.view.status(st) });
});

// Changer sa photo (étudiant)
app.post('/api/photo', auth('student'), (req, res) => {
  if (!savePhoto(req.user, req.body && req.body.photo))
    return res.status(400).json({ error: 'Photo invalide (JPEG, 300 Ko maximum)' });
  db.save();
  res.json({ user: safeUser(req.user) });
});

// Un professeur voit la photo d'un étudiant seulement s'il a scanné l'une de ses séances ou figure dans l'une de ses listes
function profCanSeeStudent(prof, studentId) {
  const st = db.data.users.find((u) => u.id === studentId && u.role === 'student');
  if (!st) return false;
  const mine = db.data.sessions.filter((x) => x.professorId === prof.id);
  if (mine.some((x) => db.data.attendances.some((a) => a.sessionId === x.id && a.studentId === studentId))) return true;
  const m = normMat(st.matricule);
  if (!m) return false;
  return mine.some((x) => (x.roster || []).some((r) => normMat(r.matricule) === m))
    || db.data.classes.some((c) => c.professorId === prof.id && c.students.some((r) => normMat(r.matricule) === m));
}
// Voir une photo : l'étudiant voit la sienne, un professeur peut voir celles des étudiants
app.get('/api/users/:id/photo', auth(), (req, res) => {
  const { id } = req.params;
  if (!/^[a-f0-9]+$/.test(id)) return res.sendStatus(404);
  if (req.user.id !== id && !(req.user.role === 'professor' && profCanSeeStudent(req.user, id))) return res.status(403).json({ error: 'Accès refusé' });
  if (!fs.existsSync(photoFile(id))) return res.sendStatus(404);
  res.setHeader('Cache-Control', 'private, max-age=86400');
  res.sendFile(photoFile(id));
});


// ---------- Listes de classes (privées par professeur) ----------
db.data.classes ||= [];
// Classe CPI 1 intégrée. Matricules au format F0000 (F + 4 chiffres).
// F0001… sont provisoires : remplacez-les par les vrais matricules des élèves.
const CPI1_TEST_STUDENTS = [
  { matricule: "F0001", name: "Bahha Saad" },
  { matricule: "F0002", name: "Adam Taalba" },
  { matricule: "F5555", name: "Ahmed Laazibi" },
  { matricule: "F0004", name: "Aya Ammari" },
  { matricule: "F0005", name: "Aniane Yousfi" },
  { matricule: "F0006", name: "Chigri Houssam Eddine" },
  { matricule: "F0007", name: "Ahlam Charai" },
  { matricule: "F0008", name: "Younes Benzirar" },
  { matricule: "F0009", name: "Rym Sadik" },
  { matricule: "F0010", name: "Abdoulilah El Ahmadi" },
  { matricule: "F0011", name: "Mohamed Amine El Farssia" },
  { matricule: "F0012", name: "Malak Zaoui" },
  { matricule: "F0013", name: "Rayhane Sadni" },
  { matricule: "F0014", name: "Mohamed Karam Salhi" },
  { matricule: "F0015", name: "Mohammed Amine Amir" },
  { matricule: "F0016", name: "Kaoutar Baroudi" },
  { matricule: "F0017", name: "Artetab Chahd" },
  { matricule: "F0018", name: "Maryem Edouiri" },
  { matricule: "F0019", name: "Fatima Zahra Soufiane" },
  { matricule: "F0020", name: "Imane Fatmi" },
  { matricule: "F0021", name: "Aboubakre Remmache" },
  { matricule: "F0022", name: "Karima Fsihi" },
  { matricule: "F0023", name: "Amina Ajelti" },
  { matricule: "F0024", name: "Zakariae Mezrhab" }
];
const normMat = (v) => String(v ?? '').trim().toLowerCase();
const ownClass = (req, res) => {
  const c = db.data.classes.find(x => x.id === req.params.id && x.professorId === req.user.id);
  if (!c) res.status(404).json({ error: 'Classe introuvable' });
  return c;
};
app.get('/api/classes', auth('professor'), (req, res) => {
  const imported = db.data.classes.filter(c => c.professorId === req.user.id)
    .map(c => ({ id:c.id, name:c.name, studentCount:c.students.length, updatedAt:c.updatedAt }));
  res.json({ classes: [{ id:'__CPI1__', name:'CPI 1', studentCount:CPI1_TEST_STUDENTS.length, test:true }, ...imported] });
});
app.get('/api/classes/:id', auth('professor'), (req,res) => {
  if (req.params.id === '__CPI1__') return res.json({ class:{id:'__CPI1__',name:'CPI 1',students:CPI1_TEST_STUDENTS,test:true} });
  const c=ownClass(req,res); if(!c) return;
  res.json({ class:{id:c.id,name:c.name,students:c.students,updatedAt:c.updatedAt} });
});
app.post('/api/classes/import', auth('professor'), async (req,res) => {
  try {
    const { name, fileName, fileData } = req.body || {};
    if (!name?.trim() || typeof fileData !== 'string') return res.status(400).json({error:'Nom de classe et fichier Excel obligatoires'});
    const buffer=Buffer.from(fileData.replace(/^data:.*?;base64,/,''),'base64');
    if(buffer.length<10 || buffer.length>5*1024*1024) return res.status(400).json({error:'Fichier invalide (5 Mo maximum)'});
    const wb=new ExcelJS.Workbook(); await wb.xlsx.load(buffer);
    const ws=wb.worksheets[0]; if(!ws) return res.status(400).json({error:'Le fichier Excel est vide'});
    const headers={};
    ws.getRow(1).eachCell((cell,col)=>{ headers[String(cell.text||'').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'')]=col; });
    const find=(...names)=>names.map(n=>headers[n]).find(Boolean);
    const mc=find('matricule','numero','numéro','code');
    const nom=find('nom','lastname'); const prenom=find('prenom','first name','firstname');
    if(!mc || !nom) return res.status(400).json({error:'Colonnes requises : Matricule, Nom et éventuellement Prénom'});
    const seen=new Set(), students=[];
    ws.eachRow((row,n)=>{ if(n===1)return;
      const matricule=String(row.getCell(mc).text||'').trim();
      const last=String(row.getCell(nom).text||'').trim();
      const first=prenom?String(row.getCell(prenom).text||'').trim():'';
      if(!matricule && !last && !first)return;
      if(!matricule || !last) throw new Error(`Ligne ${n} : matricule et nom obligatoires`);
      const key=normMat(matricule); if(seen.has(key)) throw new Error(`Matricule en double : ${matricule}`);
      seen.add(key); students.push({matricule,name:[first,last].filter(Boolean).join(' ') || last});
    });
    if(!students.length) return res.status(400).json({error:'Aucun étudiant trouvé dans le fichier'});
    let c=db.data.classes.find(x=>x.professorId===req.user.id && x.name.toLowerCase()===name.trim().toLowerCase());
    if(c){ c.students=students; c.fileName=String(fileName||'liste.xlsx'); c.updatedAt=Date.now(); }
    else { c={id:uid(),professorId:req.user.id,name:name.trim(),fileName:String(fileName||'liste.xlsx'),students,createdAt:Date.now(),updatedAt:Date.now()}; db.data.classes.push(c); }
    db.save(); res.json({class:{id:c.id,name:c.name,studentCount:c.students.length,updatedAt:c.updatedAt}});
  } catch(e){ res.status(400).json({error:e.message||'Impossible de lire le fichier Excel'}); }
});
app.put('/api/classes/:id', auth('professor'), (req,res)=>{
  const c=ownClass(req,res); if(!c)return;
  const {name}=req.body||{}; if(!name?.trim())return res.status(400).json({error:'Nom obligatoire'});
  c.name=name.trim(); c.updatedAt=Date.now(); db.save(); res.json({ok:true});
});

// ---------- Professeur ----------
app.post('/api/sessions', auth('professor'), (req, res) => {
  const { course, minutes, classId, subject, className } = req.body || {};
  if (!course) return res.status(400).json({ error: 'Nom du cours obligatoire' });
  const mins = Math.min(Math.max(parseInt(minutes) || 15, 1), 600);
  const selectedClass = classId ? db.data.classes.find(c => c.id === classId && c.professorId === req.user.id) : null;
  if (classId && !selectedClass) return res.status(404).json({ error: 'Classe introuvable' });
  const isCpi1Test = !selectedClass && String(className || '').trim().toUpperCase() === 'CPI 1';
  const s = {
    id: uid(), professorId: req.user.id, course: course.trim(), classId: selectedClass?.id || (isCpi1Test ? '__CPI1__' : null), className: selectedClass?.name || className || '', subject: subject || course.trim(), roster: selectedClass ? selectedClass.students.map(x => ({...x})) : (isCpi1Test ? CPI1_TEST_STUDENTS.map(x => ({...x})) : null),
    token: crypto.randomBytes(12).toString('hex'),
    code: crypto.randomBytes(3).toString('hex').toUpperCase(),
    createdAt: Date.now(), expiresAt: Date.now() + mins * 60000, closed: false,
  };
  db.data.sessions.push(s);
  db.save();
  res.json({ session: s });
});

app.get('/api/sessions', auth('professor'), (req, res) => {
  const list = db.data.sessions
    .filter((s) => s.professorId === req.user.id)
    .sort((a, b) => b.createdAt - a.createdAt)
    .map(({ token, code, roster, ...s }) => ({
      ...s, active: isActive(s),
      count: db.data.attendances.filter((a) => a.sessionId === s.id).length,
    }));
  res.json({ sessions: list, pendingDeviceRequests: dev.view.pendingCount() });
});

function ownSession(req, res) {
  const s = db.data.sessions.find((x) => x.id === req.params.id && x.professorId === req.user.id);
  if (!s) res.status(404).json({ error: 'Séance introuvable' });
  return s;
}
function attendeesOf(sessionId) {
  return db.data.attendances
    .filter((a) => a.sessionId === sessionId)
    .map((a) => {
      const u = db.data.users.find((x) => x.id === a.studentId) || {};
      return { name: u.name, email: u.email, matricule: u.matricule, at: a.at };
    })
    .sort((a, b) => a.at - b.at);
}

app.get('/api/sessions/:id', auth('professor'), (req, res) => {
  const s = ownSession(req, res); if (!s) return;
  const { token, code, roster, ...pub } = s;
  res.json({ session: { ...pub, active: isActive(s) }, attendees: attendeesOf(s.id) });
});

app.get('/api/sessions/:id/qr', auth('professor'), async (req, res) => {
  const s = ownSession(req, res); if (!s) return;
  if (!isActive(s)) return res.status(410).json({ error: 'Séance terminée', active: false });
  // QR dynamique : jeton signé par le serveur, valable 30 s (+ courte tolérance réseau)
  const i = qr.issue(s.token);
  res.json({ active: true, code: i.code, expiresAt: i.expiresAt, serverNow: Date.now(), intervalMs: qr.intervalMs,
    dataUrl: await QRCode.toDataURL(`${BASE_URL}/s/${i.token}`, { width: 640, margin: 2, errorCorrectionLevel: 'M' }) });
});

app.post('/api/sessions/:id/close', auth('professor'), (req, res) => {
  const s = ownSession(req, res); if (!s) return;
  s.closed = true;
  db.save();
  res.json({ ok: true });
});


async function sendExcel(res, filename, rows, meta={}) {
  const wb = new ExcelJS.Workbook(); const ws = wb.addWorksheet('Présences');
  ws.columns = [
    { header:'N°', key:'number', width:8 }, {header:'Matricule',key:'matricule',width:18},
    {header:'Nom et prénom',key:'name',width:30},{header:'Statut',key:'status',width:16},
    {header:'Date et heure du scan',key:'time',width:24}
  ];
  ws.insertRow(1,[`Rapport de présence — ${meta.className||''}`]);
  ws.mergeCells('A1:E1'); ws.getRow(1).font={bold:true,size:15,color:{argb:'FFFFFFFF'}};
  ws.getRow(1).fill={type:'pattern',pattern:'solid',fgColor:{argb:'FF183461'}};
  ws.insertRow(2,[`Professeur : ${meta.professor||''} | Matière : ${meta.subject||''} | Date : ${meta.date||''}`]);
  ws.mergeCells('A2:E2'); ws.getRow(2).font={italic:true};
  ws.insertRow(3,[`Total : ${rows.length} | Présents : ${rows.filter(x=>x.status==='Présent').length} | Absents : ${rows.filter(x=>x.status==='Absent').length}`]);
  ws.mergeCells('A3:E3');
  ws.getRow(4).values=['N°','Matricule','Nom et prénom','Statut','Date et heure du scan'];
  ws.getRow(4).font={bold:true,color:{argb:'FFFFFFFF'}};
  ws.getRow(4).fill={type:'pattern',pattern:'solid',fgColor:{argb:'FF1D4ED8'}};
  rows.forEach((r,i)=>{ const row=ws.addRow([i+1,r.matricule,r.name,r.status,r.time||'—']);
    row.eachCell(cell=>{cell.fill={type:'pattern',pattern:'solid',fgColor:{argb:r.status==='Présent'?'FFE2F4E8':'FFFCE4E4'}};cell.font={color:{argb:r.status==='Présent'?'FF166534':'FF991B1B'}};});
  });
  ws.views=[{state:'frozen',ySplit:4}];
  res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition',`attachment; filename="${filename}"`);
  await wb.xlsx.write(res); res.end();
}
const fmt = (t) => new Date(t).toLocaleString('fr-FR');
function reportRows(s) {
  const scans=db.data.attendances.filter(a=>a.sessionId===s.id);
  if(s.roster) return s.roster.map(x=>{const a=scans.find(a=>normMat((db.data.users.find(u=>u.id===a.studentId)||{}).matricule)===normMat(x.matricule));
    return {matricule:x.matricule,name:x.name,status:a?'Présent':'Absent',time:a?new Date(a.at).toLocaleString('fr-FR'):'—'};});
  return scans.map(a=>{const u=db.data.users.find(x=>x.id===a.studentId)||{};return {matricule:u.matricule||'',name:u.name||'',status:'Présent',time:new Date(a.at).toLocaleString('fr-FR')};});
}
function reportMeta(s){const p=db.data.users.find(u=>u.id===s.professorId)||{};return {className:s.className||'—',professor:p.name||'',subject:s.subject||s.course,date:new Date(s.createdAt).toLocaleDateString('fr-FR')};}
app.get('/api/sessions/:id/export', auth('professor'), async (req,res)=>{
  const s=ownSession(req,res); if(!s)return;
  await sendExcel(res,`presences-${s.course.replace(/[^\w-]+/g,'_')}.xlsx`,reportRows(s),reportMeta(s));
});
app.get('/api/export', auth('professor'), async (req,res)=>{
  const list=db.data.sessions.filter(s=>s.professorId===req.user.id).sort((a,b)=>a.createdAt-b.createdAt);
  const rows=list.flatMap(s=>reportRows(s).map(r=>({...r,name:`${s.course} — ${r.name}`})));
  await sendExcel(res,'presences-toutes-les-seances.xlsx',rows,{professor:req.user.name,className:'Historique',subject:'Toutes les matières',date:new Date().toLocaleDateString('fr-FR')});
});
app.get('/api/classes/:id/absences', auth('professor'), (req,res)=>{
  const c = req.params.id === '__CPI1__' ? {id:'__CPI1__',students:CPI1_TEST_STUDENTS} : ownClass(req,res); if(!c)return;
  const history=c.students.map(st=>({matricule:st.matricule,name:st.name,absences:db.data.sessions.filter(s=>s.professorId===req.user.id&&s.classId===c.id&&!reportRows(s).find(r=>normMat(r.matricule)===normMat(st.matricule)&&r.status==='Présent')).length}));
  res.json({history});
});
// ---------- Étudiant ----------
const attSig = (a) => sec.hmac(SECRET, `att|${a.id}|${a.sessionId}|${a.studentId}|${a.at}`).toString('hex');
const attOk = (a) => !a.sig || sec.safeEq(a.sig, attSig(a));          // les anciennes présences sans signature restent valides
app.post('/api/checkin', auth('student'), scanIpLimit, checkinLimit, (req, res) => {
  // Aucune opération asynchrone ci-dessous : vérifications + écriture forment un bloc atomique (pas de double présence possible).
  const u = req.user, ip = req.ip;
  const deny = (status, code, error, detail) => {
    dev.sec('SCAN_' + code, u, detail || error, ip);
    const since = Date.now() - 10 * 60000, log = db.data.securityLog;
    let n = 0; for (let i = log.length - 1; i >= 0 && log[i].at >= since; i--) if (log[i].userId === u.id && log[i].type.startsWith('SCAN_')) n++;
    if (n >= 5 && !log.some((l) => l.userId === u.id && l.type === 'SUSPICIOUS_ATTEMPTS' && l.at >= since)) dev.sec('SUSPICIOUS_ATTEMPTS', u, `${n} scans refusés en 10 minutes`, ip);
    db.save();
    return res.status(status).json({ error, code });
  };
  if (!sec.ipAllowed(NETWORKS, ip)) return deny(403, 'NETWORK_DENIED', 'Connectez-vous au réseau Wi-Fi de l’établissement pour valider votre présence', 'IP hors réseau autorisé');
  const ev = dev.evaluate(req, res, u);
  if (ev.state === 'blocked') return deny(403, 'DEVICE_BLOCKED', 'Ce téléphone est bloqué. Contactez l’administration.');
  if (ev.state === 'conflict') return deny(403, 'DEVICE_CONFLICT', 'Ce téléphone est associé à un autre compte étudiant');
  if (ev.state !== 'ok') return deny(403, 'DEVICE_UNAUTHORIZED', 'Téléphone non autorisé : une demande de changement est en attente de validation');

  const { token, code } = req.body || {};
  let s;
  if (typeof token === 'string' && token) {
    const p = qr.parse(token);
    s = p && db.data.sessions.find((x) => x.token === p.sessionToken);
    const v = s ? qr.verify(token, s.token) : 'invalid';
    if (v === 'expired') return deny(410, 'QR_EXPIRED', 'QR Code expiré : scannez le QR Code actuellement affiché');
    if (v !== 'ok') return deny(404, 'QR_INVALID', 'QR code invalide');
  } else if (typeof code === 'string' && code) {
    s = db.data.sessions.find((x) => isActive(x) && qr.verifyCode(code, x.token));
    if (!s) return deny(404, 'CODE_INVALID', 'Code invalide ou expiré : saisissez le code actuellement affiché');
  } else return res.status(400).json({ error: 'QR code ou code manquant' });

  if (!isActive(s)) return deny(410, 'SESSION_ENDED', 'Cette séance est terminée');
  if (s.roster && !s.roster.some((x) => normMat(x.matricule) === normMat(u.matricule))) return deny(403, 'NOT_IN_ROSTER', 'Votre matricule ne figure pas dans la liste de cette classe');
  if (db.data.attendances.some((a) => a.sessionId === s.id && a.studentId === u.id)) return deny(409, 'ALREADY_PRESENT', 'Présence déjà enregistrée pour ce cours');
  const rec = { id: uid(), sessionId: s.id, studentId: u.id, at: Date.now(), deviceId: ev.device.id, ip };
  rec.sig = attSig(rec);
  db.data.attendances.push(rec);
  db.save();
  res.json({ ok: true, course: s.course, at: rec.at });
});

app.get('/api/my-attendance', auth('student'), (req, res) => {
  const list = db.data.attendances
    .filter((a) => a.studentId === req.user.id)
    .map((a) => {
      const s = db.data.sessions.find((x) => x.id === a.sessionId) || {};
      const p = db.data.users.find((u) => u.id === s.professorId) || {};
      return { course: s.course, professor: p.name, at: a.at };
    })
    .sort((a, b) => b.at - a.at);
  res.json({ history: list });
});

// ---------- Gestion des appareils (professeur / administrateur) ----------
const idOk = (v) => typeof v === 'string' && /^[a-f0-9]{16}$/.test(v);
const qStr = (v) => String(v || '').slice(0, 60);
const staffOnly = auth('staff');
const guard = (fn) => (req, res) => { try { fn(req, res); } catch (e) { if (e.status) return res.status(e.status).json({ error: e.message }); console.error(e); res.status(500).json({ error: 'Erreur serveur' }); } };
const mustConfirm = (req) => { if (!req.body || req.body.confirm !== true) { const e = new Error('Confirmation requise'); e.status = 400; throw e; } };
const netInfo = (ip) => ip ? { ip: sec.normIp(ip), network: sec.networkOf(NETWORKS, ip), inside: NETWORKS.length ? sec.ipAllowed(NETWORKS, ip) : null } : null;
app.get('/api/devices', staffOnly, (req, res) => {
  const students = dev.view.devices(qStr(req.query.q)).map((x) => {
    let last = null; for (let i = db.data.attendances.length - 1; i >= 0; i--) if (db.data.attendances[i].studentId === x.userId) { last = db.data.attendances[i]; break; }
    return { ...x, connection: x.device ? netInfo(x.device.lastIp) : null, lastScan: last && last.ip ? { ...netInfo(last.ip), at: last.at } : null };
  });
  res.json({ students, pendingDeviceRequests: dev.view.pendingCount(), networkRestriction: NETWORKS.length > 0 });
});
app.get('/api/device-requests', staffOnly, (req, res) => res.json({ requests: dev.view.requests(qStr(req.query.q), ['pending', 'accepted', 'refused'].includes(req.query.status) ? req.query.status : '') }));
app.get('/api/device-history', staffOnly, (req, res) => res.json({ changes: dev.view.changes(qStr(req.query.q)) }));
app.get('/api/audit-log', staffOnly, (req, res) => res.json({ audit: dev.view.audit(200), security: dev.view.security(200) }));
app.post('/api/device-requests/:id/approve', staffOnly, guard((req, res) => {
  if (!idOk(req.params.id)) return res.status(404).json({ error: 'Demande introuvable' });
  mustConfirm(req); dev.approve(req.params.id, req.user, req.ip); db.save(); res.json({ ok: true });
}));
app.post('/api/device-requests/:id/refuse', staffOnly, guard((req, res) => {
  if (!idOk(req.params.id)) return res.status(404).json({ error: 'Demande introuvable' });
  mustConfirm(req); dev.refuse(req.params.id, req.user, req.body.reason, req.ip); db.save(); res.json({ ok: true });
}));
for (const [action, blocked] of [['block', true], ['unblock', false]])
  app.post(`/api/devices/:id/${action}`, staffOnly, guard((req, res) => {
    if (!idOk(req.params.id)) return res.status(404).json({ error: 'Appareil introuvable' });
    mustConfirm(req); dev.setBlocked(req.params.id, blocked, req.user, req.ip); db.save(); res.json({ ok: true });
  }));

// ---------- Statistiques et historiques ----------
const staffSessions = (u) => db.data.sessions.filter((s) => u.role === 'admin' || s.professorId === u.id);
app.get('/api/stats', staffOnly, (req, res) => {
  const list = staffSessions(req.user).sort((a, b) => b.createdAt - a.createdAt);
  const rowsOf = list.map((s) => { const r = reportRows(s), p = r.filter((x) => x.status === 'Présent').length; return { s, total: r.length, present: p }; });
  const classes = {};
  for (const { s, total, present } of rowsOf) {
    const k = s.className || '—', c = (classes[k] ||= { className: k, sessions: 0, present: 0, total: 0 });
    c.sessions++; c.present += present; c.total += total;
  }
  const ids = new Set(list.map((s) => s.id));
  res.json({
    sessions: list.length, scans: db.data.attendances.filter((a) => ids.has(a.sessionId)).length,
    integrityIssues: db.data.attendances.filter((a) => ids.has(a.sessionId) && !attOk(a)).length,
    classes: Object.values(classes).map((c) => ({ ...c, rate: c.total ? Math.round(100 * c.present / c.total) : 0 })),
    recent: rowsOf.slice(0, 15).map(({ s, total, present }) => ({ id: s.id, course: s.course, className: s.className || '—', at: s.createdAt, present, total, rate: total ? Math.round(100 * present / total) : 0 })),
  });
});
app.get('/api/students/search', staffOnly, (req, res) => {
  const q = qStr(req.query.q).trim().toLowerCase(); if (q.length < 2) return res.json({ students: [] });
  res.json({ students: db.data.users.filter((u) => u.role === 'student' && `${u.name} ${u.matricule}`.toLowerCase().includes(q)).slice(0, 15).map((u) => ({ id: u.id, name: u.name, matricule: u.matricule })) });
});
app.get('/api/students/:id/history', staffOnly, (req, res) => {
  const st = db.data.users.find((u) => u.id === req.params.id && u.role === 'student');
  if (!st) return res.status(404).json({ error: 'Étudiant introuvable' });
  const history = staffSessions(req.user).sort((a, b) => b.createdAt - a.createdAt).map((s) => {
    const r = reportRows(s).find((x) => normMat(x.matricule) === normMat(st.matricule));
    return r && { course: s.course, className: s.className || '—', at: s.createdAt, status: r.status, time: r.time };
  }).filter(Boolean);
  res.json({ student: { name: st.name, matricule: st.matricule }, present: history.filter((h) => h.status === 'Présent').length, total: history.length, history });
});

// Lien du QR code : /s/<token> -> même application
app.get('/s/:token', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`YouTube QR Attendance prêt :`);
  console.log(`  PC        -> http://localhost:${PORT}`);
  console.log(`  Téléphone -> ${BASE_URL}  (même Wi-Fi que le PC)`);
});