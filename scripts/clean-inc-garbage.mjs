// Разова чистка сміття в реєстрі накладних (1c/delivery/placed і /returned).
//
// Звідки сміття: поле накладної в рядку плану зберігалось на кожному символі ручного вводу, а
// «самолікування реєстру» робило записом плану будь-який текст. Так осідали обривки 1/10/106/…
// Причину усунуто в диспетчері (incInvValid), цей скрипт прибирає те, що вже накопичилось.
//
// Видаляє ТІЛЬКИ те, що не схоже на справжній номер (LK- + 8 цифр). Реальні накладні з міткою
// «↩проверить» НЕ чіпає — їх закриває людина кнопкою в інтерфейсі.
//
// Запуск: node delivery-scan/clean-inc-garbage.mjs [--dry]
import { readFileSync, writeFileSync } from 'node:fs';
import { createSign } from 'node:crypto';

const SA_PATH = process.env.FIREBASE_SA_FILE || 'C:\\Users\\user\\.firebase-sa.json';
const DB = 'https://lk-bauservice-bb872-default-rtdb.europe-west1.firebasedatabase.app';
const BACKUP = 'C:\\Users\\user\\AppData\\Local\\Temp\\claude\\C--Users-user\\73329b7a-1c81-4d7b-827c-2147ba1934b2\\scratchpad\\inc-garbage-backup.json';
const dry = process.argv.includes('--dry');
const VALID = /^LK-\d{8}$/;

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
  if (!j.access_token) throw new Error('нет токена: ' + JSON.stringify(j));
  return j.access_token;
}
const tok = await saToken();
const g = async (p) => (await (await fetch(DB + '/' + p + '.json', { headers: { Authorization: 'Bearer ' + tok } })).json());
const del = async (p) => (await fetch(DB + '/' + p + '.json', { method: 'DELETE', headers: { Authorization: 'Bearer ' + tok } })).status;

const backup = {};
let total = 0;
for (const node of ['placed', 'returned']) {
  const data = (await g('1c/delivery/' + node)) || {};
  const bad = Object.keys(data).filter((k) => !VALID.test(k));
  backup[node] = {};
  bad.forEach((k) => { backup[node][k] = data[k]; });
  console.log('\n' + node + ': всього ' + Object.keys(data).length + ', сміття ' + bad.length);
  bad.forEach((k) => console.log('   • ' + k));
  total += bad.length;
}
writeFileSync(BACKUP, JSON.stringify(backup, null, 2), 'utf8');
console.log('\nБекап видаленого: ' + BACKUP);

if (dry) { console.log('СУХИЙ ПРОГІН — нічого не видалено.'); process.exit(0); }
let done = 0;
for (const node of Object.keys(backup)) {
  for (const k of Object.keys(backup[node])) {
    const st = await del('1c/delivery/' + node + '/' + k);
    if (st >= 200 && st < 300) done++; else console.log('   ✗ ' + node + '/' + k + ' статус ' + st);
  }
}
console.log('Видалено: ' + done + ' з ' + total);
