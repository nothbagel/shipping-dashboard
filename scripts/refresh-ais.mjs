// Scheduled AIS refresh for the Shipping Dashboard team view (run by .github/workflows/refresh-ais.yml).
// Decrypts data.json with TEAM_PASSWORD, listens to AISStream (AISSTREAM_API_KEY) for the tracked vessels' MMSI numbers,
// merges any new positions into the vessel snapshot and writes data.json back re-encrypted. Nothing readable is written,
// and the log (public on GitHub) only shows counts - no vessel names or positions.
import fs from 'node:fs';
import { execSync } from 'node:child_process';

const FILE = 'data.json', FORMAT = 'shipping-dashboard-team-v1', ITER = 600000;
const MINUTES = Number(process.env.LISTEN_MINUTES || 10);
const KEY = (process.env.AISSTREAM_API_KEY || '').trim(), PASSWORD = process.env.TEAM_PASSWORD || '';
const NAV_STATUS = {0:'Under way', 1:'At anchor', 2:'Not under command', 3:'Restricted manoeuvrability', 4:'Constrained by draught',
  5:'Moored', 6:'Aground', 7:'Fishing', 8:'Under way (sailing)'};
const enc = new TextEncoder(), dec = new TextDecoder();
const isoNow = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');

// ---------- Encryption (same scheme as the dashboard page: PBKDF2-SHA256 -> AES-256-GCM) ----------
async function deriveKey(password, salt, iter){
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:iter, hash:'SHA-256'}, base, {name:'AES-GCM', length:256}, false, ['encrypt', 'decrypt']);
}
async function decryptPkg(pkg){
  if (!pkg || pkg.format !== FORMAT) throw new Error('data.json is not in the team format.');
  const key = await deriveKey(PASSWORD, Buffer.from(pkg.salt, 'base64'), pkg.iter);
  try { return JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM', iv:Buffer.from(pkg.iv, 'base64')}, key, Buffer.from(pkg.ct, 'base64')))); }
  catch { throw new Error('TEAM_PASSWORD does not match the published data. If the team password was changed, update the secret.'); }
}
async function encryptPkg(snapshot){
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, await deriveKey(PASSWORD, salt, ITER), enc.encode(JSON.stringify(snapshot)));
  const b64 = u => Buffer.from(u).toString('base64');
  return {format:FORMAT, kdf:'PBKDF2-SHA256', iter:ITER, salt:b64(salt), iv:b64(iv), ct:b64(new Uint8Array(ct)), publishedAt:snapshot.publishedAt};
}

// ---------- AIS parsing (same rules as the desktop app) ----------
function aisTime(t, fallback){
  const m = String(t ?? '').match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/);
  return m ? `${m[1]}T${m[2]}Z` : fallback;
}
function destCode(dest){ // last UN/LOCODE-looking token, e.g. "AUMEL - AUSYD" -> "AUSYD"
  const all = [...String(dest ?? '').toUpperCase().matchAll(/\b([A-Z]{2})\s?([A-Z]{3})\b/g)];
  return all.length ? all[all.length - 1][1] + all[all.length - 1][2] : null;
}
function etaToISO(eta, nowMs){ // AIS ETA has no year: pick the year nearest to now
  if (!eta || !eta.Month || !eta.Day) return null;
  const h = eta.Hour >= 24 ? 0 : eta.Hour || 0, mi = eta.Minute >= 60 ? 0 : eta.Minute || 0;
  let y = new Date(nowMs).getUTCFullYear(), ms = Date.UTC(y, eta.Month - 1, eta.Day, h, mi);
  if (ms < nowMs - 60 * 86400000) ms = Date.UTC(++y, eta.Month - 1, eta.Day, h, mi);
  else if (ms > nowMs + 300 * 86400000) ms = Date.UTC(--y, eta.Month - 1, eta.Day, h, mi);
  return new Date(ms).toISOString().replace('.000', '');
}
function applyMessage(results, msg, receivedIso){
  const meta = msg.MetaData || {}, body = msg.Message || {};
  if (msg.MessageType === 'PositionReport'){
    const p = body.PositionReport;
    if (!p || p.Valid === false) return null;
    const mmsi = String(meta.MMSI ?? p.UserID);
    const lat = p.Latitude ?? meta.latitude, lng = p.Longitude ?? meta.longitude;
    if (typeof lat !== 'number' || typeof lng !== 'number' || Math.abs(lat) > 90 || Math.abs(lng) > 180) return null;
    (results[mmsi] ||= {}).pos = {lat:+lat.toFixed(5), lng:+lng.toFixed(5), time:aisTime(meta.time_utc, receivedIso),
      sog:p.Sog != null && p.Sog < 102.3 ? p.Sog : null, cog:p.Cog != null && p.Cog < 360 ? p.Cog : null, nav:NAV_STATUS[p.NavigationalStatus] ?? null};
    return mmsi;
  }
  if (msg.MessageType === 'ShipStaticData'){
    const s = body.ShipStaticData;
    if (!s || s.Valid === false) return null;
    const mmsi = String(meta.MMSI ?? s.UserID);
    (results[mmsi] ||= {}).stat = {destination:String(s.Destination || '').replace(/@/g, ' ').trim(), eta:s.Eta || null};
    return mmsi;
  }
  return null;
}
function mergeIntoTracking(tracking, results, nowMs){
  for (const v of Object.values(tracking.vessels || {})){
    const r = results[String(v.mmsi)];
    if (!r) continue;
    if (r.pos){
      Object.assign(v, {lat:r.pos.lat, lng:r.pos.lng, positionTime:r.pos.time, positionSource:'AISStream (scheduled)'});
      if (r.pos.sog != null) v.speedKn = r.pos.sog;
      if (r.pos.cog != null) v.course = r.pos.cog;
      if (r.pos.nav) v.status = r.pos.nav;
      delete v.area; delete v.positionAge;
    }
    if (r.stat && r.stat.destination && r.stat.destination !== v.aisDestination){
      const code = destCode(r.stat.destination);
      if (code && v.destinationCode && code !== v.destinationCode){ v.lastPort = v.destination; v.lastPortCode = v.destinationCode; v.atd = null; }
      v.aisDestination = r.stat.destination; v.destination = r.stat.destination; v.destinationCode = code;
    }
    if (r.stat){ const eta = etaToISO(r.stat.eta, nowMs); if (eta) v.eta = eta; }
  }
  tracking.checkedAt = new Date(nowMs).toISOString().replace(/\.\d+Z$/, 'Z');
  return tracking;
}

// ---------- Listen to AISStream ----------
function listen(mmsis){
  return new Promise(resolve => {
    const results = {};
    let received = 0, confirmed = false, done = false;
    const ws = new WebSocket('wss://stream.aisstream.io/v0/stream');
    ws.binaryType = 'arraybuffer';
    const finish = why => { if (done) return; done = true; clearTimeout(timer); try { ws.close(); } catch {} resolve({results, received, why}); };
    const timer = setTimeout(() => finish('time limit'), MINUTES * 60000);
    ws.onopen = () => ws.send(JSON.stringify({APIKey:KEY, BoundingBoxes:[[[-90, -180], [90, 180]]], FiltersShipMMSI:mmsis,
      FilterMessageTypes:['PositionReport', 'ShipStaticData']}));
    ws.onmessage = ev => {
      let msg;
      try { msg = JSON.parse(typeof ev.data === 'string' ? ev.data : dec.decode(ev.data)); } catch { return; }
      if (msg.error){ console.log('AISStream reported an error.'); return finish('error'); }
      if (msg.MessageType === 'SubscriptionConfirmation'){ confirmed = true; return; }
      const m = applyMessage(results, msg, isoNow());
      if (!m || !mmsis.includes(m)) return;
      received++;
      if (mmsis.every(x => results[x] && results[x].pos && results[x].stat)) finish('all vessels reported');
    };
    ws.onerror = () => {};
    ws.onclose = () => finish(confirmed ? 'connection closed' : 'rejected');
  });
}

// ---------- Main ----------
if (!KEY || !PASSWORD){
  console.log('Missing secrets: add AISSTREAM_API_KEY and TEAM_PASSWORD under Settings > Secrets and variables > Actions.');
  process.exit(1);
}
try {
  const first = await decryptPkg(JSON.parse(fs.readFileSync(FILE, 'utf8')));
  const mmsis = Object.values((first.tracking && first.tracking.vessels) || {}).map(v => String(v.mmsi || '')).filter(Boolean);
  if (!mmsis.length){ console.log('No vessels with an MMSI in the published data - nothing to do.'); process.exit(0); }

  console.log(`Listening up to ${MINUTES} min for ${mmsis.length} vessels.`);
  const run = await listen(mmsis);
  const withPos = Object.values(run.results).filter(r => r.pos).length;
  console.log(`AIS messages: ${run.received}; vessels with a new position: ${withPos} of ${mmsis.length} (${run.why}).`);
  if (run.why === 'rejected'){ console.log('AISStream closed the connection before confirming - check the AISSTREAM_API_KEY secret.'); process.exit(1); }
  if (!run.received){ console.log('No new AIS data - data.json unchanged.'); process.exit(0); }

  // A publish may have landed while listening: merge into the latest data.json, not the one read at the start.
  if (process.env.GITHUB_ACTIONS === 'true') execSync('git pull --ff-only --quiet', {stdio:'inherit'});
  const snap = await decryptPkg(JSON.parse(fs.readFileSync(FILE, 'utf8')));
  snap.tracking = mergeIntoTracking(snap.tracking || {vessels:{}}, run.results, Date.now());
  fs.writeFileSync(FILE, JSON.stringify(await encryptPkg(snap)));
  console.log('data.json updated and re-encrypted.');
} catch (e) {
  console.log(`Refresh failed: ${e.message}`); // one clean line - the log is public
  process.exit(1);
}
