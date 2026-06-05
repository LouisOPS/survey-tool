const express    = require('express');
const session    = require('express-session');
const { Pool }   = require('pg');
const QRCode     = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const path       = require('path');
const bcrypt     = require('bcryptjs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Database (PostgreSQL) ────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Helpers pour queries lisibles
const db = {
  async get(sql, params = [])  { const r = await pool.query(sql, params); return r.rows[0] || null; },
  async all(sql, params = [])  { const r = await pool.query(sql, params); return r.rows; },
  async run(sql, params = [])  { await pool.query(sql, params); },
};

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS surveys (
      id          TEXT PRIMARY KEY,
      title       TEXT NOT NULL,
      description TEXT DEFAULT '',
      questions   TEXT NOT NULL,
      is_active   INTEGER DEFAULT 1,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS responses (
      id               TEXT PRIMARY KEY,
      survey_id        TEXT NOT NULL,
      associate_login  TEXT NOT NULL,
      answers          TEXT NOT NULL,
      submitted_at     TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(survey_id, associate_login)
    );
  `);

  // Mot de passe admin par défaut
  const existing = await db.get("SELECT value FROM settings WHERE key = $1", ['admin_password_hash']);
  if (!existing) {
    const hash = bcrypt.hashSync('admin123', 10);
    await db.run("INSERT INTO settings (key, value) VALUES ($1, $2)", ['admin_password_hash', hash]);
  }
  console.log('✅ Base de données initialisée');
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || uuidv4(),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000, secure: !!process.env.DATABASE_URL }
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  res.status(401).json({ error: 'Non autorisé' });
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/me', (req, res) => res.json({ isAdmin: !!req.session.isAdmin }));

app.post('/api/admin/login', async (req, res) => {
  try {
    const { password } = req.body;
    const row = await db.get("SELECT value FROM settings WHERE key = $1", ['admin_password_hash']);
    if (row && bcrypt.compareSync(password, row.value)) {
      req.session.isAdmin = true;
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Mot de passe incorrect' });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.post('/api/admin/change-password', requireAdmin, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6)
      return res.status(400).json({ error: 'Mot de passe trop court (min. 6 caractères)' });
    const hash = bcrypt.hashSync(newPassword, 10);
    await db.run("UPDATE settings SET value = $1 WHERE key = $2", [hash, 'admin_password_hash']);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Admin — Surveys ──────────────────────────────────────────────────────────
app.get('/api/admin/surveys', requireAdmin, async (req, res) => {
  try {
    const surveys = await db.all('SELECT id, title, description, is_active, created_at FROM surveys ORDER BY created_at DESC');
    const result = await Promise.all(surveys.map(async s => {
      const cnt = await db.get('SELECT COUNT(*) as c FROM responses WHERE survey_id = $1', [s.id]);
      return { ...s, response_count: parseInt(cnt.c) };
    }));
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/surveys', requireAdmin, async (req, res) => {
  try {
    const { title, description, questions } = req.body;
    if (!title || !Array.isArray(questions) || questions.length === 0)
      return res.status(400).json({ error: 'Titre et au moins une question sont requis' });
    const id = uuidv4();
    await db.run(
      'INSERT INTO surveys (id, title, description, questions) VALUES ($1, $2, $3, $4)',
      [id, title.trim(), (description || '').trim(), JSON.stringify(questions)]
    );
    res.json({ id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/surveys/:id', requireAdmin, async (req, res) => {
  try {
    await db.run('UPDATE surveys SET is_active = $1 WHERE id = $2', [req.body.is_active ? 1 : 0, req.params.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/surveys/:id', requireAdmin, async (req, res) => {
  try {
    await db.run('DELETE FROM responses WHERE survey_id = $1', [req.params.id]);
    await db.run('DELETE FROM surveys WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Admin — Results ──────────────────────────────────────────────────────────
app.get('/api/admin/surveys/:id/results', requireAdmin, async (req, res) => {
  try {
    const survey = await db.get('SELECT * FROM surveys WHERE id = $1', [req.params.id]);
    if (!survey) return res.status(404).json({ error: 'Sondage introuvable' });
    survey.questions = JSON.parse(survey.questions);
    const rows = await db.all('SELECT * FROM responses WHERE survey_id = $1 ORDER BY submitted_at ASC', [req.params.id]);
    const responses = rows.map(r => ({ ...r, answers: JSON.parse(r.answers) }));
    res.json({ survey, responses });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Admin — QR Code ─────────────────────────────────────────────────────────
app.get('/api/admin/surveys/:id/qr', requireAdmin, async (req, res) => {
  try {
    const survey = await db.get('SELECT id FROM surveys WHERE id = $1', [req.params.id]);
    if (!survey) return res.status(404).json({ error: 'Sondage introuvable' });
    const base = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
    const url  = `${base}/survey/${req.params.id}`;
    const qr   = await QRCode.toDataURL(url, { width: 400, margin: 2, color: { dark: '#232f3e' } });
    res.json({ qr, url });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Admin — Export CSV ───────────────────────────────────────────────────────
app.get('/api/admin/surveys/:id/export', requireAdmin, async (req, res) => {
  try {
    const survey = await db.get('SELECT * FROM surveys WHERE id = $1', [req.params.id]);
    if (!survey) return res.status(404).json({ error: 'Sondage introuvable' });
    const questions = JSON.parse(survey.questions);
    const rows = await db.all('SELECT * FROM responses WHERE survey_id = $1 ORDER BY submitted_at ASC', [req.params.id]);
    const esc = v => `"${String(v).replace(/"/g, '""')}"`;
    const headers = ['Login', 'Date', ...questions.map(q => q.text)];
    const data = rows.map(r => {
      const ans = JSON.parse(r.answers);
      return [r.associate_login, r.submitted_at, ...questions.map((_, i) => Array.isArray(ans[i]) ? ans[i].join('; ') : (ans[i] ?? ''))];
    });
    const csv = [headers, ...data].map(row => row.map(esc).join(',')).join('\r\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="sondage-${req.params.id.slice(0,8)}.csv"`);
    res.send('\uFEFF' + csv);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Public — Survey ──────────────────────────────────────────────────────────
app.get('/api/surveys/:id', async (req, res) => {
  try {
    const survey = await db.get('SELECT id, title, description, questions, is_active FROM surveys WHERE id = $1', [req.params.id]);
    if (!survey) return res.status(404).json({ error: 'Sondage introuvable' });
    survey.questions = JSON.parse(survey.questions);
    res.json(survey);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/surveys/:id/submit', async (req, res) => {
  try {
    const { login, answers } = req.body;
    if (!login || !login.trim()) return res.status(400).json({ error: 'Login requis' });

    const survey = await db.get('SELECT * FROM surveys WHERE id = $1', [req.params.id]);
    if (!survey) return res.status(404).json({ error: 'Sondage introuvable' });
    if (!survey.is_active) return res.status(403).json({ error: 'Ce sondage est fermé' });

    const cleanLogin = login.trim().toLowerCase();
    const questions  = JSON.parse(survey.questions);

    for (let i = 0; i < questions.length; i++) {
      const a = answers[i];
      if (a === undefined || a === null || a === '' || (Array.isArray(a) && !a.length))
        return res.status(400).json({ error: `Réponse manquante pour la question ${i + 1}` });
    }

    await db.run(
      'INSERT INTO responses (id, survey_id, associate_login, answers) VALUES ($1, $2, $3, $4)',
      [uuidv4(), req.params.id, cleanLogin, JSON.stringify(answers)]
    );
    res.json({ success: true });
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Vous avez déjà participé à ce sondage' });
    res.status(500).json({ error: e.message });
  }
});

// ─── Pages ────────────────────────────────────────────────────────────────────
app.get('/admin',       (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/survey/:id',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'survey.html')));
app.get('/health',      (req, res) => res.json({ status: 'ok' }));

// ─── WhatsApp & WebArchive Export ────────────────────────────────────────────
app.get('/api/admin/surveys/:id/whatsapp',    requireAdmin, waExport('html'));
app.get('/api/admin/surveys/:id/webarchive',  requireAdmin, waExport('webarchive'));

function waExport(format) {
  return async (req, res) => {
    try {
      const survey   = await db.get('SELECT * FROM surveys WHERE id = $1', [req.params.id]);
      if (!survey) return res.status(404).json({ error: 'Sondage introuvable' });
      const waNumber = (req.query.number || '').replace(/\D/g, '');
      if (!waNumber || waNumber.length < 8) return res.status(400).json({ error: 'Numéro invalide' });
      const questions = JSON.parse(survey.questions);
      const html      = generateOfflineHTML(survey.title, survey.description || '', questions, waNumber);
      const slug      = survey.title.replace(/[^a-z0-9]/gi, '-').toLowerCase().slice(0, 30);
      if (format === 'html') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="sondage-${slug}.html"`);
        res.send(html);
      } else {
        const b64 = Buffer.from(html, 'utf-8').toString('base64');
        const archive = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>WebMainResource</key><dict>
    <key>WebResourceData</key><data>${b64}</data>
    <key>WebResourceMIMEType</key><string>text/html</string>
    <key>WebResourceTextEncodingName</key><string>UTF-8</string>
    <key>WebResourceURL</key><string>about:blank</string>
  </dict>
  <key>WebSubresources</key><array/>
</dict></plist>`;
        res.setHeader('Content-Type', 'application/x-webarchive');
        res.setHeader('Content-Disposition', `attachment; filename="sondage-${slug}.webarchive"`);
        res.send(archive);
      }
    } catch(e) { res.status(500).json({ error: e.message }); }
  };
}

// ─── Start ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    const base = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
    console.log(`\n📋 Outil de Sondage — ${base}`);
    console.log(`   Admin : ${base}/admin\n`);
  });
}).catch(err => { console.error('❌ Erreur DB:', err.message); process.exit(1); });

// ─── generateOfflineHTML ──────────────────────────────────────────────────────
function generateOfflineHTML(title, desc, questions, waNumber) {
  const qJson     = JSON.stringify(questions);
  const safeTitle = title.replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const safeDesc  = desc.replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>${safeTitle}</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;color:#232f3e;min-height:100vh}.hdr{background:#1a2332;padding:14px 18px;display:flex;align-items:center;gap:10px;position:sticky;top:0}.hdr h1{color:#fff;font-size:15px;font-weight:700;flex:1}.wrap{max-width:580px;margin:0 auto;padding:16px 14px}.card{background:#fff;border-radius:12px;padding:20px;box-shadow:0 2px 10px rgba(0,0,0,.07);margin-bottom:12px}.hero{text-align:center;padding:20px 10px}.hero h2{font-size:19px;font-weight:800;margin-bottom:8px}.lbl{display:block;font-size:13px;font-weight:700;margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em}input[type=text]{width:100%;padding:14px 16px;border:2px solid #e5e7eb;border-radius:10px;font-size:16px;font-family:inherit;-webkit-appearance:none}input:focus{outline:none;border-color:#ff9900}.q-card{background:#fff;border-radius:12px;padding:18px;box-shadow:0 2px 10px rgba(0,0,0,.07);margin-bottom:10px}.q-num{font-size:11px;font-weight:800;color:#ff9900;text-transform:uppercase;margin-bottom:5px}.q-txt{font-size:15px;font-weight:700;margin-bottom:12px;line-height:1.4}.req{color:#ef4444}.opts{display:flex;flex-direction:column;gap:8px}.opt{display:flex;align-items:center;gap:11px;padding:13px 16px;border:2px solid #e5e7eb;border-radius:10px;cursor:pointer;font-size:14px;user-select:none}.opt.sel{border-color:#ff9900;background:#fff7ed}input[type=radio],input[type=checkbox]{width:18px;height:18px;accent-color:#ff9900;flex-shrink:0}textarea{width:100%;padding:12px 16px;border:2px solid #e5e7eb;border-radius:10px;font-size:14px;font-family:inherit;resize:vertical;min-height:80px;-webkit-appearance:none}textarea:focus{outline:none;border-color:#ff9900}.rating{display:flex;gap:7px;justify-content:center;margin-bottom:5px}.rb{width:52px;height:52px;border:2px solid #e5e7eb;border-radius:11px;font-size:19px;font-weight:800;cursor:pointer;background:#fff;display:flex;align-items:center;justify-content:center}.rb.sel{border-color:#ff9900;background:#ff9900;color:#fff}.rl{display:flex;justify-content:space-between;font-size:11px;color:#6b7280;padding:0 3px}.prog{height:4px;background:#e5e7eb;border-radius:3px;margin-bottom:4px}.prog-f{height:100%;background:#ff9900;border-radius:3px;transition:width .3s}.prog-t{font-size:12px;color:#6b7280;text-align:right;margin-bottom:14px}.btn{display:block;width:100%;padding:16px;background:#ff9900;color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:800;cursor:pointer;-webkit-appearance:none;margin-top:8px}.wa-btn{display:block;width:100%;padding:16px;background:#25D366;color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:800;text-decoration:none;text-align:center;margin-top:8px}.err{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;padding:12px;border-radius:10px;font-size:13px;margin:8px 0}.screen{text-align:center;padding:32px 16px}.screen .icon{font-size:52px;margin-bottom:12px}.screen h2{font-size:20px;font-weight:800;margin-bottom:8px}.screen p{color:#6b7280;font-size:14px;line-height:1.6;margin-bottom:18px}</style></head>
<body><div class="hdr"><span style="font-size:20px">&#x1F4CB;</span><h1>${safeTitle}</h1></div>
<div class="wrap" id="root">
<div class="card hero"><h2>${safeTitle}</h2>${safeDesc ? `<p>${safeDesc}</p>` : ''}</div>
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
