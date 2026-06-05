import express  from 'express';
import session  from 'express-session';
import { Database } from 'bun:sqlite';
import QRCode   from 'qrcode';
import { v4 as uuidv4 } from 'uuid';
import { createRequire } from 'module';
import path     from 'path';
import { fileURLToPath } from 'url';
import bcrypt   from 'bcryptjs';

const require   = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Database ─────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'data.db'));
db.exec('PRAGMA journal_mode=WAL;');
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS surveys (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT DEFAULT '',
    questions TEXT NOT NULL, is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS responses (
    id TEXT PRIMARY KEY, survey_id TEXT NOT NULL, associate_login TEXT NOT NULL,
    answers TEXT NOT NULL, submitted_at TEXT DEFAULT (datetime('now')),
    UNIQUE(survey_id, associate_login)
  );
`);

function setting(key, def) {
  return db.query('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? def;
}
function setSetting(key, val) {
  const e = db.query('SELECT key FROM settings WHERE key = ?').get(key);
  if (e) db.query('UPDATE settings SET value=? WHERE key=?').run(val, key);
  else   db.query('INSERT INTO settings (key,value) VALUES (?,?)').run(key, val);
}

// Default admin password
if (!setting('admin_password_hash')) setSetting('admin_password_hash', bcrypt.hashSync('admin123', 10));

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'local-dev-secret',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  if (req.session?.isAdmin) return next();
  res.status(401).json({ error: 'Non autorisé' });
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/api/admin/login', (req, res) => {
  const hash = setting('admin_password_hash', '');
  if (!hash || !bcrypt.compareSync(req.body.password || '', hash))
    return res.status(401).json({ error: 'Mot de passe incorrect' });
  req.session.isAdmin = true;
  res.json({ ok: true });
});
app.post('/api/admin/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });
app.get('/api/admin/me', (req, res) => res.json({ isAdmin: !!req.session?.isAdmin }));
app.post('/api/admin/change-password', auth, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Mot de passe trop court' });
  setSetting('admin_password_hash', bcrypt.hashSync(newPassword, 10));
  res.json({ ok: true });
});

// ─── Surveys (admin) ──────────────────────────────────────────────────────────
app.get('/api/admin/surveys', auth, (req, res) => {
  res.json(db.query('SELECT * FROM surveys ORDER BY created_at DESC').all());
});
app.post('/api/admin/surveys', auth, (req, res) => {
  const { title, description, questions } = req.body;
  if (!title || !questions?.length) return res.status(400).json({ error: 'Titre et questions requis' });
  const id = uuidv4();
  db.query('INSERT INTO surveys (id,title,description,questions) VALUES (?,?,?,?)')
    .run(id, title, description || '', JSON.stringify(questions));
  res.json({ id });
});
app.put('/api/admin/surveys/:id', auth, (req, res) => {
  const { title, description, questions, is_active } = req.body;
  db.query('UPDATE surveys SET title=?,description=?,questions=?,is_active=? WHERE id=?')
    .run(title, description || '', JSON.stringify(questions), is_active ? 1 : 0, req.params.id);
  res.json({ ok: true });
});
app.delete('/api/admin/surveys/:id', auth, (req, res) => {
  db.query('DELETE FROM responses WHERE survey_id=?').run(req.params.id);
  db.query('DELETE FROM surveys WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ─── Results + Stats ──────────────────────────────────────────────────────────
app.get('/api/admin/surveys/:id/results', auth, (req, res) => {
  const survey = db.query('SELECT * FROM surveys WHERE id=?').get(req.params.id);
  if (!survey) return res.status(404).json({ error: 'Sondage non trouvé' });
  const responses = db.query('SELECT * FROM responses WHERE survey_id=? ORDER BY submitted_at DESC').all(req.params.id);
  res.json({
    ...survey,
    questions: JSON.parse(survey.questions),
    responses: responses.map(r => ({ ...r, answers: JSON.parse(r.answers) }))
  });
});

// ─── QR Code ──────────────────────────────────────────────────────────────────
app.get('/api/admin/surveys/:id/qr', auth, async (req, res) => {
  const base = getPublicUrl();
  const url  = `${base}/survey.html?id=${req.params.id}`;
  const qr   = await QRCode.toDataURL(url, { width: 400, margin: 2 });
  res.json({ qr, url });
});

function getPublicUrl() {
  try {
    const f = path.join(__dirname, '.public-url');
    if (require('fs').existsSync(f)) return require('fs').readFileSync(f, 'utf8').trim();
  } catch(_) {}
  return `http://localhost:${PORT}`;
}

// ─── Export CSV ───────────────────────────────────────────────────────────────
app.get('/api/admin/surveys/:id/export', auth, (req, res) => {
  const survey = db.query('SELECT * FROM surveys WHERE id=?').get(req.params.id);
  if (!survey) return res.status(404).json({ error: 'Sondage non trouvé' });
  const questions = JSON.parse(survey.questions);
  const responses = db.query('SELECT * FROM responses WHERE survey_id=? ORDER BY submitted_at').all(req.params.id);
  const headers = ['login', 'date', ...questions.map((_,i) => `Q${i+1}`)];
  const rows = responses.map(r => {
    const a = JSON.parse(r.answers);
    return [r.associate_login, r.submitted_at, ...questions.map((_,i) => {
      const v = a[i]; return Array.isArray(v) ? v.join(' | ') : String(v ?? '');
    })];
  });
  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="sondage-${req.params.id.slice(0,8)}.csv"`);
  res.send('\uFEFF' + csv); // BOM pour Excel
});

// ─── Export WhatsApp HTML / WebArchive ────────────────────────────────────────
app.get('/api/admin/surveys/:id/whatsapp', auth, (req, res) => {
  const survey = db.query('SELECT * FROM surveys WHERE id=?').get(req.params.id);
  if (!survey) return res.status(404).json({ error: 'Sondage non trouvé' });
  const wa  = req.query.number || '';
  const html = generateOfflineHTML(survey.title, survey.description, JSON.parse(survey.questions), wa);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="sondage-${survey.id.slice(0,8)}.html"`);
  res.send(html);
});
app.get('/api/admin/surveys/:id/webarchive', auth, (req, res) => {
  const survey = db.query('SELECT * FROM surveys WHERE id=?').get(req.params.id);
  if (!survey) return res.status(404).json({ error: 'Sondage non trouvé' });
  const wa  = req.query.number || '';
  const html = generateOfflineHTML(survey.title, survey.description, JSON.parse(survey.questions), wa);
  const b64  = Buffer.from(html).toString('base64');
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>WebMainResource</key><dict>
  <key>WebResourceData</key><data>${b64}</data>
  <key>WebResourceFrameName</key><string></string>
  <key>WebResourceMIMEType</key><string>text/html</string>
  <key>WebResourceTextEncodingName</key><string>UTF-8</string>
  <key>WebResourceURL</key><string>about:blank</string>
</dict></dict></plist>`;
  res.setHeader('Content-Type', 'application/x-webarchive');
  res.setHeader('Content-Disposition', `attachment; filename="sondage-${survey.id.slice(0,8)}.webarchive"`);
  res.send(plist);
});

// ─── Publish to GitHub Pages ──────────────────────────────────────────────────
app.post('/api/admin/surveys/:id/publish', auth, async (req, res) => {
  const survey = db.query('SELECT * FROM surveys WHERE id=?').get(req.params.id);
  if (!survey) return res.status(404).json({ error: 'Sondage non trouvé' });

  const token = setting('github_token', '');
  const owner = setting('github_owner', '');
  const repo  = setting('github_repo', '');
  if (!token || !owner || !repo)
    return res.status(400).json({ error: 'Token GitHub non configuré. Va dans ⚙ Paramètres > GitHub.' });

  const wa       = req.body.number || '';
  const html     = generateOfflineHTML(survey.title, survey.description, JSON.parse(survey.questions), wa);
  const b64      = Buffer.from(html).toString('base64');
  const filePath = `surveys/survey-${survey.id}.html`;
  const apiUrl   = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}`;
  const ghHdr    = { Authorization: `token ${token}`, 'Content-Type': 'application/json', 'User-Agent': 'survey-tool' };

  let sha;
  try {
    const chk = await fetch(apiUrl, { headers: ghHdr });
    if (chk.ok) sha = (await chk.json()).sha;
  } catch(_) {}

  const body = { message: `Publish survey ${survey.id.slice(0,8)}`, content: b64 };
  if (sha) body.sha = sha;

  const r = await fetch(apiUrl, { method: 'PUT', headers: ghHdr, body: JSON.stringify(body) });
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    return res.status(500).json({ error: `Erreur GitHub: ${err.message || r.status}` });
  }

  const pageUrl = `https://${owner}.github.io/${repo}/${filePath}`;
  const qr = await QRCode.toDataURL(pageUrl, { width: 400, margin: 2 });
  res.json({ url: pageUrl, qr });
});

// ─── GitHub Settings ──────────────────────────────────────────────────────────
app.get('/api/admin/settings/github', auth, (req, res) => {
  res.json({
    hasToken: !!setting('github_token'),
    owner: setting('github_owner', ''),
    repo:  setting('github_repo', ''),
  });
});
app.post('/api/admin/settings/github', auth, (req, res) => {
  const { token, owner, repo } = req.body;
  if (token) setSetting('github_token', token);
  if (owner) setSetting('github_owner', owner);
  if (repo)  setSetting('github_repo', repo);
  res.json({ ok: true });
});

// ─── Public survey response ───────────────────────────────────────────────────
app.get('/api/survey/:id', (req, res) => {
  const s = db.query('SELECT * FROM surveys WHERE id=? AND is_active=1').get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Sondage non trouvé ou fermé' });
  res.json({ ...s, questions: JSON.parse(s.questions) });
});
app.post('/api/responses', (req, res) => {
  const { survey_id, associate_login, answers } = req.body;
  if (!survey_id || !associate_login || !answers) return res.status(400).json({ error: 'Données manquantes' });
  if (!db.query('SELECT id FROM surveys WHERE id=? AND is_active=1').get(survey_id))
    return res.status(404).json({ error: 'Sondage non trouvé' });
  try {
    db.query('INSERT INTO responses (id,survey_id,associate_login,answers) VALUES (?,?,?,?)')
      .run(uuidv4(), survey_id, associate_login.trim().toLowerCase(), JSON.stringify(answers));
    res.json({ ok: true });
  } catch(e) {
    if (e.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Déjà répondu' });
    throw e;
  }
});

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true }));

// ─── generateOfflineHTML ──────────────────────────────────────────────────────
function generateOfflineHTML(title, desc, questions, waNumber) {
  const qJson = JSON.stringify(questions);
  const st = s => String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>${st(title)}</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;color:#232f3e;min-height:100vh}.hdr{background:#1a2332;padding:14px 18px;display:flex;align-items:center;gap:10px;position:sticky;top:0}.hdr h1{color:#fff;font-size:15px;font-weight:700;flex:1}.wrap{max-width:580px;margin:0 auto;padding:16px 14px}.card{background:#fff;border-radius:12px;padding:20px;box-shadow:0 2px 10px rgba(0,0,0,.07);margin-bottom:12px}.hero{text-align:center;padding:20px 10px}.hero h2{font-size:19px;font-weight:800;margin-bottom:8px}.lbl{display:block;font-size:13px;font-weight:700;margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em}input[type=text]{width:100%;padding:14px 16px;border:2px solid #e5e7eb;border-radius:10px;font-size:16px;font-family:inherit;-webkit-appearance:none}input:focus{outline:none;border-color:#ff9900}.q-card{background:#fff;border-radius:12px;padding:18px;box-shadow:0 2px 10px rgba(0,0,0,.07);margin-bottom:10px}.q-num{font-size:11px;font-weight:800;color:#ff9900;text-transform:uppercase;margin-bottom:5px}.q-txt{font-size:15px;font-weight:700;margin-bottom:12px;line-height:1.4}.req{color:#ef4444}.opts{display:flex;flex-direction:column;gap:8px}.opt{display:flex;align-items:center;gap:11px;padding:13px 16px;border:2px solid #e5e7eb;border-radius:10px;cursor:pointer;font-size:14px;user-select:none}.opt.sel{border-color:#ff9900;background:#fff7ed}input[type=radio],input[type=checkbox]{width:18px;height:18px;accent-color:#ff9900;flex-shrink:0}textarea{width:100%;padding:12px 16px;border:2px solid #e5e7eb;border-radius:10px;font-size:14px;font-family:inherit;resize:vertical;min-height:80px;-webkit-appearance:none}textarea:focus{outline:none;border-color:#ff9900}.rating{display:flex;gap:7px;justify-content:center;margin-bottom:5px}.rb{width:52px;height:52px;border:2px solid #e5e7eb;border-radius:11px;font-size:19px;font-weight:800;cursor:pointer;background:#fff;display:flex;align-items:center;justify-content:center}.rb.sel{border-color:#ff9900;background:#ff9900;color:#fff}.rl{display:flex;justify-content:space-between;font-size:11px;color:#6b7280;padding:0 3px}.prog{height:4px;background:#e5e7eb;border-radius:3px;margin-bottom:4px}.prog-f{height:100%;background:#ff9900;border-radius:3px;transition:width .3s}.prog-t{font-size:12px;color:#6b7280;text-align:right;margin-bottom:14px}.btn{display:block;width:100%;padding:16px;background:#ff9900;color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:800;cursor:pointer;-webkit-appearance:none;margin-top:8px}.wa-btn{display:block;width:100%;padding:16px;background:#25D366;color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:800;text-decoration:none;text-align:center;margin-top:8px}.err{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;padding:12px;border-radius:10px;font-size:13px;margin:8px 0}.screen{text-align:center;padding:32px 16px}.screen .icon{font-size:52px;margin-bottom:12px}.screen h2{font-size:20px;font-weight:800;margin-bottom:8px}.screen p{color:#6b7280;font-size:14px;line-height:1.6;margin-bottom:18px}</style></head>
<body><div class="hdr"><span style="font-size:20px">&#x1F4CB;</span><h1>${st(title)}</h1></div>
<div class="wrap" id="root">
<div class="card hero"><h2>${st(title)}</h2>${desc ? `<p>${st(desc)}</p>` : ''}</div>
<div class="card" id="step-login">
  <div style="margin-bottom:14px"><label class="lbl">Ton login Amazon <span class="req">*</span></label>
  <input type="text" id="login-val" placeholder="ex: jdupont" autocapitalize="none" autocorrect="off" spellcheck="false"></div>
  <div id="login-err"></div>
  <button class="btn" type="button" onclick="startSurvey()">Commencer &#x2192;</button>
</div></div>
<script>
var Q=${qJson};var WA='${waNumber}';var TITLE=${JSON.stringify(title)};var login='';var answers={};
function get(i){return document.getElementById(i);}
function startSurvey(){var v=(get('login-val').value||'').trim();if(!v){get('login-err').innerHTML='<div class="err">Saisis ton login Amazon.</div>';return;}login=v;get('root').innerHTML=buildQ();up();}
function buildQ(){var n=Q.length,h='<div class="prog"><div class="prog-f" id="pf" style="width:0%"></div></div><div class="prog-t" id="pt">0/'+n+' r\u00E9pondu'+(n>1?'s':'')+'</div>';Q.forEach(function(q,i){h+='<div class="q-card"><div class="q-num">Q'+(i+1)+'/'+n+'</div><div class="q-txt">'+esc(q.text)+' <span class="req">*</span></div>';if(q.type==='radio'||q.type==='checkbox'){h+='<div class="opts">';(q.options||[]).forEach(function(opt,oi){h+='<label class="opt" id="ol-'+i+'-'+oi+'" onclick="sel(this,'+i+',\''+esc(opt)+'\','+(q.type==='checkbox'?'1':'0')+')">';h+='<input type="'+q.type+'" name="q'+i+'" value="'+esc(opt)+'" style="pointer-events:none"> '+esc(opt)+'</label>';});h+='</div>';}else if(q.type==='text'){h+='<textarea id="ta-'+i+'" placeholder="Ta r\u00E9ponse..." oninput="answers['+i+']=this.value.trim();up()"></textarea>';}else if(q.type==='rating'){h+='<div class="rating">';for(var r=1;r<=5;r++)h+='<button type="button" class="rb" id="rb-'+i+'-'+r+'" onclick="setR('+i+','+r+')">'+r+'</button>';h+='</div><div class="rl"><span>Mauvais</span><span>Excellent</span></div>';}h+='</div>';});h+='<div id="sub-err"></div><button class="btn" type="button" onclick="doSubmit()">Envoyer &#x2192;</button><div style="height:32px"></div>';return h;}
function sel(lbl,qi,val,multi){if(!multi){document.querySelectorAll('[id^="ol-'+qi+'-"]').forEach(function(el){el.classList.remove('sel');var i=el.querySelector('input');if(i)i.checked=false;});lbl.classList.add('sel');var i=lbl.querySelector('input');if(i)i.checked=true;answers[qi]=val;}else{lbl.classList.toggle('sel');var i2=lbl.querySelector('input');if(i2)i2.checked=!i2.checked;answers[qi]=Array.from(document.querySelectorAll('input[name="q'+qi+'"]:checked')).map(function(e){return e.value;});}up();}
function setR(qi,v){answers[qi]=v;for(var r=1;r<=5;r++){var b=get('rb-'+qi+'-'+r);if(b)b.classList.toggle('sel',r<=v);}up();}
function up(){var done=0;Q.forEach(function(q,i){var a=answers[i];if(q.type==='text'&&a&&a.trim())done++;else if(q.type==='rating'&&a)done++;else if(q.type==='radio'&&a)done++;else if(q.type==='checkbox'&&Array.isArray(a)&&a.length)done++;});var pf=get('pf'),pt=get('pt');if(pf)pf.style.width=(Q.length?done/Q.length*100:0)+'%';if(pt)pt.textContent=done+'/'+Q.length+' r\u00E9pondu'+(Q.length>1?'s':'');}
function doSubmit(){var e=get('sub-err');e.innerHTML='';for(var i=0;i<Q.length;i++){var a=answers[i],q=Q[i];if(a===undefined||a===null||a===''||(Array.isArray(a)&&!a.length)){e.innerHTML='<div class="err">R\u00E9ponds \u00E0 la question '+(i+1)+'.</div>';document.querySelectorAll('.q-card')[i].scrollIntoView({behavior:'smooth',block:'center'});return;}}var msg='Sondage: '+TITLE+'\nLogin: '+login+'\n\n';Q.forEach(function(q,i){var a=answers[i],s=Array.isArray(a)?a.join(', '):(q.type==='rating'?a+'/5':String(a));msg+=(i+1)+'. '+q.text+'\n   '+s+'\n\n';});get('root').innerHTML='<div class="card screen"><div class="icon">&#x2705;</div><h2 style="color:#16a34a">Merci !</h2><p>Tes r\u00E9ponses sont pr\u00EAtes.</p><a class="wa-btn" href="https://wa.me/'+WA+'?text='+encodeURIComponent(msg.trim())+'" target="_blank">&#x1F4AC; Envoyer par WhatsApp</a></div>';}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;');}
<\/script></body></html>`;
}

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅  Serveur : http://localhost:${PORT}/admin   (admin123)\n`);
});
