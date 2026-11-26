// Mini base de données JSON (0 DH, aucune installation) : data/db.json
const fs = require('fs');
const path = require('path');
const FILE = path.join(__dirname, 'data', 'db.json');
let data = { users: [], sessions: [], attendances: [], classes: [] };

function save() {
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, FILE);
}
fs.mkdirSync(path.dirname(FILE), { recursive: true });
if (fs.existsSync(FILE)) { data = JSON.parse(fs.readFileSync(FILE, 'utf8')); data.classes ||= []; }
else save();

module.exports = { data, save };
