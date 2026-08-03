// Разова чистка коментарів у вже створених заявках: прибрати службове
// «Дополнение к заказу № LK-… от … …», яке 1С дописує в комментарий.
//
// Причину усунуто в диспетчері (cleanNote), цей скрипт чистить те, що вже лягло в rows.
// Логіку НЕ дублюємо: cleanNote витягується з самого index.html.txt.
//
// Запуск: node delivery-scan/clean-row-comments.mjs [--dry]
import { readFileSync, writeFileSync } from 'node:fs';
import { createSign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const DISP = join(HERE, '..', 'security-A', 'deploy', 'index.html.txt');
const SA_PATH = process.env.FIREBASE_SA_FILE || 'C:\\Users\\user\\.firebase-sa.json';
const DB = 'https://lk-bauservice-bb872-default-rtdb.europe-west1.firebasedatabase.app';
const BACKUP = 'C:\\Users\\user\\AppData\\Local\\Temp\\claude\\C--Users-user\\73329b7a-1c81-4d7b-827c-2147ba1934b2\\scratchpad\\row-comments-backup.json';
const dry = process.argv.includes('--dry');

function grabFn(src, name) {
  const start = src.indexOf('function ' + name + '(');
  if (start === -1) throw new Error('не знайдено ' + name);
  let depth = 0;
  for (let j = src.indexOf('{', start); j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}') { depth--; if (depth === 0) return src.slice(start, j + 1); }
  }
  throw new Error('не закрито ' + name);
}
const src = readFileSync(DISP, 'utf8');
const reLine = (src.match(/var _DOP_RE\s*=[^\n]*/) || [])[0];
if (!reLine) throw new Error('не знайдено _DOP_RE');
const { cleanNote } = new Function(reLine + '\n' + grabFn(src, 'cleanNote') + '\nreturn {cleanNote:cleanNote};')();

const sa = JSON.parse(readFileSync(SA_PATH, 'utf8'));
const b64u = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function saToken() {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64u(JSON.stringify({
    iss: sa.client_email, scope: 'https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email',
    aud: 'https://oauth2.googleapis.com/token', exp: now + 3600, iat: now
  }));
  const s = createSign('RSA-SHA256'); s.update(head + '.' + claim); s.end();
  const jwt = head + '.' + claim + '.' + b64u(s.sign(sa.private_key));
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' + jwt
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('нет токена');
  return j.access_token;
}
const tok = await saToken();
const g = async (p) => (await (await fetch(DB + '/' + p + '.json', { headers: { Authorization: 'Bearer ' + tok } })).json());
const patch = async (p, v) => (await fetch(DB + '/' + p + '.json', {
  method: 'PATCH', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: JSON.stringify(v)
})).status;

const rows = (await g('rows')) || {};
const changes = [];
for (const id of Object.keys(rows)) {
  const r = rows[id] || {};
  const before = r.comment;
  if (!before || typeof before !== 'string') continue;
  // ЛИШЕ ті, де є службова фраза. Інакше зачепили б сотню старих заявок, де cleanNote просто
  // підчистив би зайву кому в кінці — а нас про це не просили, і чіпати квітневі записи ні до чого.
  if (before.indexOf('Дополнение к заказу') === -1) continue;
  const after = cleanNote(before);
  if (after !== before.trim()) changes.push({ id, date: r.date || '', addr: r.addr || '', before, after });
}
console.log('Заявок з коментарем-сміттям: ' + changes.length + (dry ? ' (СУХИЙ ПРОГІН)' : ''));
changes.slice(0, 12).forEach((c) => {
  console.log('  ' + c.date + ' ' + (c.addr || '—'));
  console.log('     було:  |' + c.before + '|');
  console.log('     стане: |' + c.after + '|');
});
if (changes.length > 12) console.log('  … ще ' + (changes.length - 12));

writeFileSync(BACKUP, JSON.stringify(changes, null, 2), 'utf8');
console.log('\nБекап: ' + BACKUP);
if (dry) { console.log('СУХИЙ ПРОГІН — нічого не змінено.'); process.exit(0); }

let done = 0;
for (const c of changes) {
  const st = await patch('rows/' + c.id, { comment: c.after });
  if (st >= 200 && st < 300) done++; else console.log('   ✗ ' + c.id + ' статус ' + st);
}
console.log('Очищено: ' + done + ' з ' + changes.length);
