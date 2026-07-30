// Хмарний авто-аналіз маршрутів (GitHub Actions, ~23:00 пн-сб).
// Делает то же, что кнопка «Проанализировать» в диспетчере, но САМ, по всем авто за день.
// Логика портирована из security-A/deploy/index.html (raPoints/raKpi/одометр-кластер/raFact).
// ⚠ При правках расчёта в index.html — синхронизировать здесь.
import crypto from 'crypto';

const DB='https://lk-bauservice-bb872-default-rtdb.europe-west1.firebasedatabase.app';
const SA=JSON.parse(process.env.FIREBASE_SA||'{}');
const MAPS_KEY=process.env.MAPS_KEY||'';
if(!SA.client_email||!MAPS_KEY){ console.error('Нет FIREBASE_SA или MAPS_KEY'); process.exit(1); }

const b64=s=>Buffer.from(s).toString('base64url');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function saToken(){
  const now=Math.floor(Date.now()/1000);
  const si=b64(JSON.stringify({alg:'RS256',typ:'JWT'}))+'.'+b64(JSON.stringify({iss:SA.client_email,scope:'https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email',aud:'https://oauth2.googleapis.com/token',iat:now,exp:now+3600}));
  const s=crypto.createSign('RSA-SHA256');s.update(si);s.end();
  const jwt=si+'.'+s.sign(SA.private_key).toString('base64url');
  const r=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion='+jwt});
  return (await r.json()).access_token;
}

// ── портированные ЧИСТЫЕ функции (синхронизировать с index.html) ──
function raNum(v){ var n=Number(v); return (v===null||v===''||typeof v==='boolean'||!isFinite(n))?null:n; }
function cleanAddr(a){ return String(a||'').replace(/\s*\d*[A-Za-zА-Яа-я]*_[A-Za-zА-Яа-я]+\s*$/,'').replace(/,?\s*\d+\s*(OG|EG|DG)\w*\s*$/i,'').trim(); }
function addrQ(p){ return cleanAddr(p.addr)+', '+(p.city||'')+', Germany'; }
function raPoints(rowsArr,drv,date){
  var uniq={};
  (rowsArr||[]).forEach(function(r){
    if(!r||r.drv!==drv||r.date!==date)return;
    if(!r.addr||!String(r.addr).trim())return;
    if(r.inRoute===false)return;
    var key=((r.city||'')+'|'+(r.addr||'')).toLowerCase().replace(/\s+/g,' ').trim();
    var ts=null; if(r.photoTs&&r.photoTs.length){var a=r.photoTs.filter(Boolean).map(Number).sort(function(x,y){return x-y;});ts=a[0]||null;}
    var isDrv=!!r.fromDriver;
    if(!uniq[key])uniq[key]={city:r.city||'',addr:String(r.addr).trim(),order:(r.order!=null?r.order:1e9),ts:ts,who:(isDrv?'driver':'disp'),dupes:0,lat:null,lon:null};
    else uniq[key].dupes++;
    var u=uniq[key];
    if(r.order!=null&&r.order<u.order)u.order=r.order;
    if(ts&&(!u.ts||ts<u.ts))u.ts=ts;
    if(!isDrv)u.who='disp'; // плановая строка ПЕРЕВЕШИВАЕТ (как в UI): адрес с плановой И водительской строкой остаётся planned
    if(u.lat==null&&r.doneLat!=null&&r.doneLon!=null){u.lat=r.doneLat;u.lon=r.doneLon;}
  });
  var all=[];for(var k in uniq)if(uniq.hasOwnProperty(k))all.push(uniq[k]);
  return {planned:all.filter(function(p){return p.who!=='driver';}).sort(function(a,b){return a.order-b.order;}),
          added:all.filter(function(p){return p.who==='driver';}).sort(function(a,b){return (a.ts||0)-(b.ts||0);})};
}
function raKpi(factKm,planKm,optKm){
  var r1=function(v){return Math.round(v*10)/10;};
  var fact=(factKm!=null&&isFinite(factKm))?r1(factKm):null;
  var loss=(planKm!=null&&optKm!=null)?r1(planKm-optKm):null;
  var extra=(fact!=null&&planKm!=null)?r1(fact-planKm):null;
  return {factKm:fact,planKm:(planKm!=null?planKm:null),optKm:(optKm!=null?optKm:null),
    lossKm:loss,lossPct:(loss!=null&&optKm)?Math.round(loss/optKm*100):null,
    extraKm:extra,extraPct:(extra!=null&&planKm)?Math.round(extra/planKm*100):null};
}
// одометр-кластер (параметризован odoAll/cfg вместо глобалей браузера)
var ODO_TOL_BACK=60,ODO_SAME_DAY_CAP=900,ODO_DAY_KM=1500,ODO_HARD_MAX=30000,ODO_BAND=60000,ODO_SOFT_RATE=800,ODO_REBASE_TOL=400;
function odoMachines(cfg){
  if(cfg&&cfg.machines&&typeof cfg.machines==='object'){
    var out=[]; Object.keys(cfg.machines).forEach(function(id){var m=cfg.machines[id]||{};out.push({id:id,label:(m.label||('Машина '+id)),region:(m.region==='nord'?'nord':'main'),seed:(+m.seed||0)});});
    if(out.length)return out;
  }
  return [{id:'A',label:'Машина A',region:'main',seed:637700},{id:'B',label:'Машина B',region:'main',seed:321500},{id:'C',label:'Машина C',region:'nord',seed:469800}];
}
function odoIsNordDrv(cfg,k){ if(k==='C')return true; var o=cfg&&cfg.drivers&&cfg.drivers[k]; return !!(o&&o.nord===true); }
function odoDayNum(date){ var p=(''+(date||'')).split('-'); if(p.length!==3)return 0; return Date.UTC(+p[0],+p[1]-1,+p[2])/86400000; }
function odoTsEff(x,date,m){ if(x&&typeof x.ts==='number'&&x.ts>0)return x.ts; var base=Date.parse(date+'T00:00:00Z'); if(isNaN(base))base=0; return base+(m==='start'?8:17)*3600000; }
function odoEvents(odoAll,cfg){
  var a=[];
  Object.keys(odoAll||{}).forEach(function(drv){ var bd=odoAll[drv]||{};
    Object.keys(bd).forEach(function(date){ var r=bd[date]||{};
      // ev = журнал событий (с 30.07): смена машины среди дня + указанная водителем машина.
      // Есть журнал — берём только его, иначе start/end продублировались бы.
      var _ev=r.ev, _has={};
      if(_ev&&typeof _ev==='object'){
        Object.keys(_ev).forEach(function(k){ var x=_ev[k]||{}; if(typeof x.km!=='number'||isNaN(x.km))return;
          var kind=x.kind||'start'; _has[kind]=1;
          a.push({drv:drv,date:date,m:((kind==='end'||kind==='swap_out')?'end':'start'),kind:kind,van:(x.van||null),km:x.km,tsEff:odoTsEff(x,date,kind),photo:(x.photo||''),drvNord:odoIsNordDrv(cfg,drv)});
        });
      }
      // ПЕРЕХОДНЫЙ ДЕНЬ: начал на старой версии, закончил на новой — журнал неполный.
      // Берём из старой структуры то, чего в журнале НЕТ, иначе потеряем начало дня.
      ['start','end'].forEach(function(m){ if(_has[m])return; var x=r[m];
        if(x&&typeof x.km==='number'&&!isNaN(x.km)){ a.push({drv:drv,date:date,m:m,kind:m,van:(x.van||null),km:x.km,tsEff:odoTsEff(x,date,m),photo:(x.photo||''),drvNord:odoIsNordDrv(cfg,drv)}); }
      });
    });
  });
  a.sort(function(x,y){ if(x.tsEff!==y.tsEff)return x.tsEff-y.tsEff; if(x.date!==y.date)return x.date<y.date?-1:1; return x.m===y.m?0:(x.m==='start'?-1:1); });
  return a;
}
function odoCluster(odoAll,cfg){
  var evs=odoEvents(odoAll,cfg), vans=odoMachines(cfg);
  vans.forEach(function(v){ v.cur=null; v.lastDate=null; v.evs=[]; v.sf=null; });
  var unknown=[];
  evs.forEach(function(e){
    var best=null,bd=Infinity;
    // машину указал сам водитель (с 30.07) — не гадаем
    if(e.van){ vans.forEach(function(v){ if(v.id===e.van){ best=v; bd=0; } }); }
    if(!best){
      vans.forEach(function(v){ var ref=(v.cur!=null?v.cur:v.seed); var d=Math.abs(e.km-ref); if(d<bd){ bd=d; best=v; } });
      if(!best||bd>ODO_BAND){ e.flag='unknown'; unknown.push(e); return; }
    }
    var v=best; e.vanId=v.id; e.vanRegion=v.region; e.cross=((v.region==='nord')!==e.drvNord);
    if(v.cur===null){ v.cur=e.km; v.lastDate=e.date; e.clean=true; e.flag='first'; e.delta=null; v.evs.push(e); return; }
    var gap=e.km-v.cur, el=Math.max(1,odoDayNum(e.date)-odoDayNum(v.lastDate)), sd=(e.date===v.lastDate);
    var fw=sd?ODO_SAME_DAY_CAP:ODO_DAY_KM*el;
    if(gap>=-ODO_TOL_BACK && gap<=fw && gap<=ODO_HARD_MAX){
      e.clean=true;
      if(gap>0){ e.delta=gap; if(!sd)e.carry=true; v.cur=e.km; v.lastDate=e.date; v.sf=null; }
      else { e.delta=0; v.lastDate=e.date; }
    } else {
      e.clean=false; e.delta=null;
      if(gap>=-ODO_TOL_BACK){ if(v.sf!==null && Math.abs(e.km-v.sf)<=ODO_REBASE_TOL){ v.cur=Math.min(e.km,v.sf); v.lastDate=e.date; v.sf=null; e.clean=true; e.delta=0; } else { v.sf=e.km; } }
    }
    v.evs.push(e);
  });
  return {vans:vans,unknown:unknown};
}
// Отрезок = «водитель был за рулём ЭТОЙ машины с километра A до километра B». Открывается на
// start/swap_in, закрывается на end/swap_out. Пробег водителя = сумма его отрезков.
// ⛔Почему не приростами событий: событие «сел в авто» даёт прирост, который накатал ПРЕДЫДУЩИЙ
// водитель этой машины (она стояла не с нуля). Считая приростами, чужой пробег приписали бы тому,
// кто только что сел — а на этих цифрах висят зарплата и штрафы.
function odoSegments(cluster){
  var out=[];
  ((cluster&&cluster.vans)||[]).forEach(function(v){
    var open={};
    (v.evs||[]).slice().sort(function(x,y){return x.tsEff-y.tsEff;}).forEach(function(e){
      var key=e.drv+'|'+e.date, kind=(e.kind||e.m);
      if(kind==='start'||kind==='swap_in'){ open[key]={drv:e.drv,date:e.date,kmFrom:e.km,tsFrom:e.tsEff,clean:(e.clean!==false),declared:!!e.van}; return; }
      if(kind==='end'||kind==='swap_out'){
        var o=open[key]; if(!o)return;
        var km=e.km-o.kmFrom;
        // declared = машину указал водитель на ОБОИХ концах отрезка. Только такие дни считаем
        // отрезками; старые дни (машина угадана) остаются на прежнем расчёте, чтобы история не поехала.
        out.push({drv:o.drv,date:o.date,van:v.id,kmFrom:o.kmFrom,kmTo:e.km,km:km,tsFrom:o.tsFrom,tsTo:e.tsEff,clean:(o.clean&&e.clean!==false&&km>=0),declared:(o.declared&&!!e.van)});
        delete open[key];
      }
    });
  });
  out.sort(function(x,y){return x.tsFrom-y.tsFrom;});
  return out;
}
// факт как «Пробег»: сумма чистых суточных приростов по машине; carry/cross/typo — мягкая пометка
function raFact(cluster,drv,date){
  var out={km:null,soft:false,why:'',reason:''};
  // машина указана водителем → считаем отрезками, иначе припишем ему чужой пробег
  var _seg=odoSegments(cluster).filter(function(s){return s.declared&&s.drv===drv&&s.date===date;});
  if(_seg.length){
    var _t=0,_bad=false;
    _seg.forEach(function(s){ if(s.km>0)_t+=s.km; if(s.clean===false)_bad=true; });
    out.km=_t; out.soft=_bad; out.why=_bad?'есть сомнительное показание одометра':'';
    return out;
  }
  var km=0,has=false,notes={};
  ((cluster&&cluster.vans)||[]).forEach(function(v){ (v.evs||[]).forEach(function(e){
    if(!e||e.drv!==drv||e.date!==date)return;
    var d=raNum(e.delta);
    if(e.clean!==false&&d!=null&&d>0){ km+=d; has=true; if(e.carry)notes.carry=1; if(e.cross)notes.cross=1; }
    else if(e.clean===false){ notes.typo=1; }
  }); });
  ((cluster&&cluster.unknown)||[]).forEach(function(e){ if(e&&e.drv===drv&&e.date===date)notes.unk=1; });
  var note=function(n){var a=[];if(n.carry)a.push('часть пробега накоплена с прошлых дней (утром замер не сделали)');if(n.cross)a.push('есть показание другого региона');if(n.typo)a.push('часть показаний не сходится — возможна опечатка');if(n.unk)a.push('одно показание не привязалось к машине');return a.join('; ');};
  if(has){ out.km=Math.round(km*10)/10; if(Object.keys(notes).length){ out.soft=true; out.why=note(notes); } }
  else out.reason=Object.keys(notes).length?note(notes):'за этот день нет показаний одометра';
  return out;
}

// ── сеть ──
async function geocode(q){
  const r=await fetch('https://nominatim.openstreetmap.org/search?format=json&limit=1&countrycodes=de&q='+encodeURIComponent(q),
    {headers:{'User-Agent':'LKBau-route-analysis/1.0 (s.kozorizz@gmail.com)'}});
  const a=await r.json();
  return (a&&a[0])?{lat:parseFloat(a[0].lat),lon:parseFloat(a[0].lon)}:null;
}
async function directions(startCity,qs,optimize){
  if(!qs.length)return null;
  const o=encodeURIComponent(startCity.indexOf(',')>0?startCity:(startCity+', Germany'));
  const wps=qs.map(encodeURIComponent);
  const url='https://maps.googleapis.com/maps/api/directions/json?origin='+o+'&destination='+o+
    '&waypoints='+(optimize?'optimize:true|':'')+wps.join('|')+'&key='+MAPS_KEY+'&language=de';
  const j=await (await fetch(url)).json();
  if(!j||j.status!=='OK')return {err:(j&&j.status)||'ERR'};
  const legs=j.routes[0].legs; let m=0,sec=0; legs.forEach(l=>{m+=l.distance.value;sec+=l.duration.value;});
  return {km:Math.round(m/100)/10,min:Math.round(sec/60),poly:(j.routes[0].overview_polyline||{}).points||''};
}

// ── main ──
const tok=await saToken();
if(!tok){ console.error('нет токена Firebase'); process.exit(1); }
const g=async p=>(await (await fetch(DB+'/'+p+'.json',{headers:{Authorization:'Bearer '+tok}})).json());
const put=async(p,v)=>(await fetch(DB+'/'+p+'.json',{method:'PUT',headers:{Authorization:'Bearer '+tok,'Content-Type':'application/json'},body:JSON.stringify(v)})).status;

const argDate=process.argv[2]; // ручной прогон конкретного дня: node route-analysis-cron.mjs 2026-07-25
const date=argDate||new Date().toISOString().slice(0,10); // в 21:00 UTC = 23:00 Berlin, тот же календарный день
const rowsObj=await g('rows')||{}; const rows=Object.values(rowsObj);
const cfg=await g('cfg')||{};
const odoAll=await g('odometer')||{};
let geoCache=await g('geo_cache')||{};
const cluster=odoCluster(odoAll,cfg);

// все авто (drv), у кого есть маршрут за этот день
const drvs=[...new Set(rows.filter(r=>r&&r.date===date&&r.addr&&String(r.addr).trim()&&r.inRoute!==false).map(r=>r.drv))].filter(Boolean);
console.log('Дата '+date+' · авто с маршрутом: '+(drvs.length?drvs.join(', '):'нет'));
let done=0,skip=0,fail=0,geoNew=0;

for(const drv of drvs){
  try{
    const P=raPoints(rows,drv,date);
    if(!P.planned.length){ console.log('  '+drv+': нет плановых точек — пропуск'); skip++; continue; }
    const startCity=(cfg.drivers&&cfg.drivers[drv]&&cfg.drivers[drv].startCity)||'Wilhelmshaven';
    if(P.planned.length>25){ console.log('  '+drv+': >25 плановых точек ('+P.planned.length+') — Google не примет, пропуск'); skip++; continue; }
    const all=P.planned.concat(P.added);
    // геокод базы ДО сборки data (иначе base=null и на карте нет маркера базы на первом прогоне)
    const bq=(startCity.indexOf(',')>0?startCity:startCity+', Germany'), bKey=b64(bq);
    if(!geoCache[bKey]){ const bc=await geocode(bq); await sleep(1100); if(bc){geoCache[bKey]={lat:bc.lat,lon:bc.lon};geoNew++;} }
    // геокод точек (общий кэш в Firebase + Nominatim с паузой)
    for(const p of all){
      const q=addrQ(p); const key=b64(q);
      if(geoCache[key]){ p.glat=geoCache[key].lat; p.glon=geoCache[key].lon; continue; }
      const c=await geocode(q); await sleep(1100);
      if(c){ p.glat=c.lat; p.glon=c.lon; geoCache[key]={lat:c.lat,lon:c.lon}; geoNew++; }
    }
    const pq=P.planned.map(addrQ);
    const plan=await directions(startCity,pq,false);
    const opt=await directions(startCity,pq,true);
    const err=(plan&&plan.err)||(opt&&opt.err)||null;
    if(err){ console.log('  '+drv+': Google '+err+' — не сохраняем (не затираем прежний расчёт)'); fail++; continue; }
    const fa=raFact(cluster,drv,date);
    const planKm=(plan&&plan.km!=null)?plan.km:null, optKm=(opt&&opt.km!=null)?opt.km:null;
    const data={ drv:drv, date:date, ts:Date.now(), startCity:startCity, auto:true,
      base:(geoCache[bKey]||null),
      kpi:raKpi(fa.km,planKm,optKm), factSoft:!!fa.soft, factWhy:fa.why||'', factReason:fa.reason||'',
      planKm:planKm, planMin:(plan&&plan.min)||null, optKm:optKm, optMin:(opt&&opt.min)||null,
      poly:(plan&&plan.poly)||'', planned:P.planned, added:P.added,
      odo:(odoAll[drv]&&odoAll[drv][date])||null, err:null };
    const st=await put('route_analysis/'+drv+'/'+date,data);
    console.log('  '+drv+': сохранено ('+st+') · план '+planKm+' / оптимум '+optKm+' км · не сплан. '+(P.added.length)+'/'+all.length+' · факт '+(fa.km!=null?fa.km+' км':(fa.reason||'—')));
    done++;
  }catch(e){ console.log('  '+drv+': ошибка '+(e&&e.message||e)); fail++; }
}
if(geoNew)await put('geo_cache',geoCache);
console.log('Итог: сохранено '+done+', пропущено '+skip+', сбой '+fail+', геокод новых '+geoNew);
