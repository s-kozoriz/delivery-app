// Разовый добор отрезков «водитель × машина» за прошлые дни в odo_segments.
//
// Зачем: вечерний робот пишет отрезки только за свой день, а KL тянет диапазон дат. Чтобы у них
// сразу была история, добираем прошлые дни отдельно.
//
// ⛔Google здесь НЕ используется: отрезки считаются только по одометру. Прогонять вечерний робот
// за каждый прошлый день ради этого нельзя — он дёргал бы платные Directions и упирался в лимит.
//
// Логика НЕ дублируется: функции odoEvents/odoCluster/odoSegments вынимаются из самого
// route-analysis-cron.mjs — так исключено расхождение с вечерним расчётом.
//
// Запуск: node scripts/backfill-odo-segments.mjs 2026-07-01 2026-07-30 [--dry]
import { readFileSync } from 'node:fs';
import { createSign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SA_PATH = process.env.FIREBASE_SA_FILE || 'C:\\Users\\user\\.firebase-sa.json';
const DB = 'https://lk-bauservice-bb872-default-rtdb.europe-west1.firebasedatabase.app';

const from = process.argv[2], to = process.argv[3];
const dry = process.argv.includes('--dry');
if (!from || !to) { console.error('Укажите диапазон: node scripts/backfill-odo-segments.mjs 2026-07-01 2026-07-30 [--dry]'); process.exit(1); }

// ── функции считаются ТЕМ ЖЕ кодом, что и вечером ──
function grabFn(src, name) {
  const start = src.indexOf('function ' + name + '(');
  if (start === -1) throw new Error('не найдена функция ' + name);
  let depth = 0;
  for (let j = src.indexOf('{', start); j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}') { depth--; if (depth === 0) return src.slice(start, j + 1); }
  }
  throw new Error('не закрыта функция ' + name);
}
const cronSrc = readFileSync(join(HERE, 'route-analysis-cron.mjs'), 'utf8');
const consts = (cronSrc.match(/var ODO_TOL_BACK[^\n]*/) || [''])[0];
const names = ['odoMachines', 'odoIsNordDrv', 'odoDayNum', 'odoTsEff', 'odoEvents', 'odoCluster', 'odoSegments', 'klStops'];
const odo = new Function(consts + '\n' + names.map((n) => grabFn(cronSrc, n)).join('\n') +
  '\nreturn {odoCluster:odoCluster,odoSegments:odoSegments,klStops:klStops};')();

// ── Firebase service account -> access token ──
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
const put = async (p, v) => (await fetch(DB + '/' + p + '.json', {
  method: 'PUT', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: JSON.stringify(v)
})).status;

const cfg = (await g('cfg')) || {};
const odoAll = (await g('odometer')) || {};
const rows = Object.values((await g('rows')) || {});
const cluster = odo.odoCluster(odoAll, cfg);
const all = odo.odoSegments(cluster).filter((s) => s.date >= from && s.date <= to);

const byKey = {};
all.forEach((s) => { const k = s.drv + '|' + s.date; (byKey[k] = byKey[k] || []).push(s); });
const keys = Object.keys(byKey).sort();
console.log('Диапазон ' + from + '…' + to + ' · дней-водителей с пробегом: ' + keys.length + (dry ? ' (СУХОЙ ПРОГОН)' : ''));

let saved = 0, declared = 0, guessed = 0;
for (const k of keys) {
  const list = byKey[k];
  const [drv, date] = k.split('|');
  let km = 0, dec = true, clean = true;
  list.forEach((s) => { if (s.km > 0) km += s.km; if (!s.declared) dec = false; if (s.clean === false) clean = false; });
  if (dec) declared++; else guessed++;
  const rec = {
    drv, date, ts: Date.now(), km,
    source: dec ? 'declared' : 'guessed',
    flag: clean ? (dec ? 'ok' : 'guessed') : 'check',
    segments: list.map((s) => ({ van: s.van, odo_start: s.kmFrom, odo_end: s.kmTo, km: s.km, ts_from: s.tsFrom, ts_to: s.tsTo, clean: s.clean !== false })),
    stops: odo.klStops(rows, drv, date)
  };
  if (dry) { console.log('  ' + date + ' ' + drv + ' km=' + km + ' ' + rec.flag + ' отрезков=' + list.length); continue; }
  const st = await put('odo_segments/' + drv + '/' + date, rec);
  if (st >= 200 && st < 300) saved++;
  else console.log('  ✗ ' + k + ' статус ' + st);
}
console.log(dry ? 'Сухой прогон: ничего не записано.' : ('Записано: ' + saved + ' из ' + keys.length + ' · с указанной машиной: ' + declared + ', угадано: ' + guessed));
