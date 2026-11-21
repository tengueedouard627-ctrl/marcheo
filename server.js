require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const Anthropic = require('@anthropic-ai/sdk');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 16) { console.error('JWT_SECRET manquant ou trop court (.env)'); process.exit(1); }
const DATA = path.resolve(process.env.DATA_DIR || './data');
const UP = path.join(DATA, 'uploads'), OUT = path.join(DATA, 'out');
[UP, OUT].forEach(d => fs.mkdirSync(d, { recursive: true }));
const FONT = process.env.FONT_FILE || '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf';
const ai = process.env.ANTHROPIC_API_KEY ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;

// Offres : modifiez les prix et quotas ici
const PLANS = {
  essai:      { label: 'Essai gratuit', price: 0,     videos: 1 },
  essentiel:  { label: 'Essentiel',     price: 2500,  videos: 10 },
  pro:        { label: 'Pro',           price: 5000,  videos: 30 },
  business:   { label: 'Business',      price: 10000, videos: 100 }
};
const PAY_NUMBERS = { orange: '65623071', telmob: '01832287' };

const db = new Database(path.join(DATA, 'marcheo.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, phone TEXT UNIQUE NOT NULL, name TEXT, pass TEXT NOT NULL,
  role TEXT DEFAULT 'merchant', plan TEXT DEFAULT 'essai', plan_expires INTEGER DEFAULT 0,
  used INTEGER DEFAULT 0, created_at INTEGER);
CREATE TABLE IF NOT EXISTS payments(
  id INTEGER PRIMARY KEY, user_id INTEGER, plan TEXT, amount INTEGER, operator TEXT,
  reference TEXT, status TEXT DEFAULT 'pending', created_at INTEGER, decided_at INTEGER);
CREATE TABLE IF NOT EXISTS videos(
  id INTEGER PRIMARY KEY, user_id INTEGER, status TEXT DEFAULT 'queued', shop TEXT, product TEXT,
  price TEXT, city TEXT, lang TEXT, photos TEXT, post TEXT, script TEXT, error TEXT, created_at INTEGER);
`);

const app = express();
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));
const upload = multer({
  dest: UP, limits: { fileSize: 8 * 1024 * 1024, files: 6 },
  fileFilter: (req, f, cb) => cb(null, /^image\/(jpeg|png|webp)$/.test(f.mimetype))
});

const now = () => Date.now();
const sign = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
const auth = (req, res, next) => {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(jwt.verify(t, SECRET).id);
    if (!u) throw new Error('no user');
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Connexion requise' }); }
};
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Réservé à l’administrateur' });
const effective = u => (u.plan !== 'essai' && u.plan_expires > now()) ? u.plan : 'essai';
const publicUser = u => {
  const plan = effective(u);
  return { id: u.id, phone: u.phone, name: u.name, role: u.role, plan, plan_label: PLANS[plan].label,
    plan_expires: u.plan_expires, videos_left: Math.max(0, PLANS[plan].videos - u.used) };
};

// ---------- Comptes ----------
app.post('/api/register', (req, res) => {
  const phone = String(req.body.phone || '').replace(/[\s+\-]/g, '');
  const pass = String(req.body.password || '');
  if (!/^\d{8,15}$/.test(phone)) return res.status(400).json({ error: 'Numéro de téléphone invalide' });
  if (pass.length < 6) return res.status(400).json({ error: 'Mot de passe : 6 caractères minimum' });
  if (db.prepare('SELECT 1 FROM users WHERE phone=?').get(phone)) return res.status(409).json({ error: 'Ce numéro a déjà un compte' });
  const role = process.env.ADMIN_PHONE && phone === process.env.ADMIN_PHONE.replace(/\D/g, '') ? 'admin' : 'merchant';
  const r = db.prepare('INSERT INTO users(phone,name,pass,role,created_at) VALUES(?,?,?,?,?)')
    .run(phone, String(req.body.name || '').slice(0, 80), bcrypt.hashSync(pass, 10), role, now());
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);
  res.json({ token: sign(u), user: publicUser(u) });
});
app.post('/api/login', (req, res) => {
  const phone = String(req.body.phone || '').replace(/[\s+\-]/g, '');
  const u = db.prepare('SELECT * FROM users WHERE phone=?').get(phone);
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.pass)) return res.status(401).json({ error: 'Numéro ou mot de passe incorrect' });
  res.json({ token: sign(u), user: publicUser(u) });
});
app.get('/api/me', auth, (req, res) => res.json(publicUser(req.user)));
app.get('/api/plans', (req, res) => res.json({ plans: PLANS, pay_numbers: PAY_NUMBERS }));

// ---------- Paiements (validation manuelle au départ) ----------
app.post('/api/payments', auth, (req, res) => {
  const plan = req.body.plan, operator = req.body.operator;
  if (!PLANS[plan] || plan === 'essai') return res.status(400).json({ error: 'Offre invalide' });
  if (!PAY_NUMBERS[operator]) return res.status(400).json({ error: 'Opérateur invalide' });
  const reference = String(req.body.reference || '').slice(0, 60);
  if (reference.length < 4) return res.status(400).json({ error: 'Indiquez la référence de la transaction' });
  if (db.prepare("SELECT 1 FROM payments WHERE reference=? AND operator=?").get(reference, operator))
    return res.status(409).json({ error: 'Cette référence est déjà enregistrée' });
  const r = db.prepare('INSERT INTO payments(user_id,plan,amount,operator,reference,created_at) VALUES(?,?,?,?,?,?)')
    .run(req.user.id, plan, PLANS[plan].price, operator, reference, now());
  res.json({ id: r.lastInsertRowid, status: 'pending' });
});
app.get('/api/payments', auth, (req, res) =>
  res.json(db.prepare('SELECT * FROM payments WHERE user_id=? ORDER BY id DESC').all(req.user.id)));

app.get('/api/admin/payments', auth, admin, (req, res) =>
  res.json(db.prepare(`SELECT p.*, u.phone, u.name FROM payments p JOIN users u ON u.id=p.user_id
    WHERE p.status=? ORDER BY p.id DESC`).all(req.query.status || 'pending')));
app.post('/api/admin/payments/:id/approve', auth, admin, (req, res) => {
  const p = db.prepare("SELECT * FROM payments WHERE id=? AND status='pending'").get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Paiement introuvable ou déjà traité' });
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.user_id);
  const start = Math.max(now(), u.plan === p.plan ? u.plan_expires : 0);
  db.transaction(() => {
    db.prepare("UPDATE payments SET status='approved', decided_at=? WHERE id=?").run(now(), p.id);
    db.prepare('UPDATE users SET plan=?, plan_expires=?, used=0 WHERE id=?').run(p.plan, start + 30 * 864e5, p.user_id);
  })();
  res.json({ ok: true });
});
app.post('/api/admin/payments/:id/reject', auth, admin, (req, res) => {
  db.prepare("UPDATE payments SET status='rejected', decided_at=? WHERE id=? AND status='pending'").run(now(), req.params.id);
  res.json({ ok: true });
});

// ---------- Vidéos ----------
app.post('/api/videos', auth, upload.array('photos', 6), (req, res) => {
  const u = req.user, plan = effective(u);
  if (u.used >= PLANS[plan].videos) {
    (req.files || []).forEach(f => fs.unlink(f.path, () => {}));
    return res.status(402).json({ error: 'Quota atteint : choisissez une offre pour continuer' });
  }
  const b = req.body, shop = String(b.shop || '').trim().slice(0, 60), product = String(b.product || '').trim().slice(0, 80);
  if (!shop || !product) return res.status(400).json({ error: 'Boutique et produit obligatoires' });
  const r = db.transaction(() => {
    db.prepare('UPDATE users SET used=used+1 WHERE id=?').run(u.id);
    return db.prepare('INSERT INTO videos(user_id,shop,product,price,city,lang,photos,created_at) VALUES(?,?,?,?,?,?,?,?)')
      .run(u.id, shop, product, String(b.price || '').slice(0, 30), String(b.city || '').slice(0, 40),
        String(b.lang || 'Français').slice(0, 40), JSON.stringify((req.files || []).map(f => f.path)), now());
  })();
  res.json({ id: r.lastInsertRowid, status: 'queued' });
});
app.get('/api/videos', auth, (req, res) =>
  res.json(db.prepare('SELECT id,status,shop,product,post,error,created_at FROM videos WHERE user_id=? ORDER BY id DESC').all(req.user.id)));
app.get('/api/videos/:id', auth, (req, res) => {
  const v = db.prepare('SELECT id,user_id,status,shop,product,post,error FROM videos WHERE id=?').get(req.params.id);
  if (!v || (v.user_id !== req.user.id && req.user.role !== 'admin')) return res.status(404).json({ error: 'Introuvable' });
  res.json(v);
});
app.get('/api/videos/:id/file', auth, (req, res) => {
  const v = db.prepare('SELECT user_id,status FROM videos WHERE id=?').get(req.params.id);
  if (!v || v.status !== 'done' || (v.user_id !== req.user.id && req.user.role !== 'admin')) return res.status(404).end();
  res.sendFile(path.join(OUT, `${req.params.id}`, 'final.mp4'));
});

// ---------- Texte (IA) ----------
async function writeContent(v) {
  const fb = {
    slogan: `${v.product} · ${v.shop}`,
    lines: ['Qualité et bon prix', `Disponible à ${v.city || 'votre ville'}`, 'Commandez maintenant !'],
    post: `🔥 ${v.shop} : ${v.product}${v.price ? ' à ' + v.price : ''}${v.city ? ' – ' + v.city : ''}\nCommandez maintenant !`
  };
  if (!ai) return fb;
  try {
    const r = await ai.messages.create({
      model: process.env.CLAUDE_MODEL || 'claude-sonnet-5-5', max_tokens: 600,
      messages: [{ role: 'user', content:
        `Tu écris une courte pub vidéo pour un commerçant africain. Langue : ${v.lang}. Boutique : ${v.shop}. Produit : ${v.product}. ` +
        `Prix : ${v.price || 'non précisé'}. Ville : ${v.city || 'non précisée'}. Réponds UNIQUEMENT en JSON : ` +
        `{"slogan":"6 mots max","lines":["3 phrases de 6 mots max"],"post":"message WhatsApp de 3 lignes, 2 emojis, appel à commander, sans promesse ni chiffre inventé"}` }]
    });
    const j = JSON.parse(r.content[0].text.replace(/```json|```/g, '').trim());
    return (j.slogan && Array.isArray(j.lines) && j.post) ? j : fb;
  } catch (e) { console.error('IA:', e.message); return fb; }
}

// ---------- Rendu vidéo (FFmpeg) ----------
const run = (args) => new Promise((ok, ko) => execFile('ffmpeg', ['-y', '-loglevel', 'error', ...args], (e, so, se) => e ? ko(new Error(se || e.message)) : ok()));
const wrapText = (t, w) => { const out = []; let l = ''; for (const x of String(t).split(' ')) { if ((l + ' ' + x).trim().length > w && l) { out.push(l); l = x; } else l = (l + ' ' + x).trim(); } out.push(l); return out.join('\n'); };
const COLORS = ['0xe8590c', '0x2b8a3e', '0x5f3dc4', '0xc2255c'];

async function processVideo(v) {
  const photos = JSON.parse(v.photos).filter(p => fs.existsSync(p));
  const c = await writeContent(v);
  db.prepare('UPDATE videos SET post=?, script=? WHERE id=?').run(c.post, JSON.stringify(c), v.id);
  const dir = path.join(OUT, String(v.id)); fs.mkdirSync(dir, { recursive: true });
  const n = Math.max(3, photos.length), D = 2.6;
  const texts = [c.slogan, ...c.lines]; while (texts.length < n) texts.push(v.shop); texts.length = n;
  const list = [];
  for (let i = 0; i < n; i++) {
    const tf = path.join(dir, `t${i}.txt`), sf = path.join(dir, `s${i}.txt`), clip = path.join(dir, `c${i}.mp4`);
    fs.writeFileSync(tf, wrapText(texts[i], 16));
    const sub = i === n - 1 ? [v.price, v.city].filter(Boolean).join(' - ') : (i === 0 ? v.shop : '');
    fs.writeFileSync(sf, sub || ' ');
    const input = photos.length ? ['-loop', '1', '-t', String(D), '-i', photos[i % photos.length]]
                                : ['-f', 'lavfi', '-i', `color=c=${COLORS[i % 4]}:s=720x1280:d=${D}`];
    const vf = [
      'scale=720:1280:force_original_aspect_ratio=increase', 'crop=720:1280', 'format=yuv420p',
      'drawbox=y=ih*0.55:w=iw:h=ih*0.45:color=black@0.55:t=fill',
      `drawtext=fontfile=${FONT}:textfile=${tf}:fontcolor=white:fontsize=54:line_spacing=10:x=(w-text_w)/2:y=h*0.62`,
      `drawtext=fontfile=${FONT}:textfile=${sf}:fontcolor=0xffd43b:fontsize=42:x=(w-text_w)/2:y=h*0.88`,
      'fade=t=in:d=0.4'
    ].join(',');
    await run([...input, '-vf', vf, '-r', '30', '-t', String(D), '-c:v', 'libx264', '-pix_fmt', 'yuv420p', clip]);
    list.push(`file '${clip}'`);
  }
  const lf = path.join(dir, 'list.txt'); fs.writeFileSync(lf, list.join('\n'));
  await run(['-f', 'concat', '-safe', '0', '-i', lf, '-c', 'copy', path.join(dir, 'final.mp4')]);
  photos.forEach(p => fs.unlink(p, () => {}));
  fs.readdirSync(dir).filter(f => /^(t|s|c)\d|list/.test(f)).forEach(f => fs.unlink(path.join(dir, f), () => {}));
}

let busy = false;
setInterval(async () => {
  if (busy) return;
  const v = db.prepare("SELECT * FROM videos WHERE status='queued' ORDER BY id LIMIT 1").get();
  if (!v) return;
  busy = true;
  db.prepare("UPDATE videos SET status='processing' WHERE id=?").run(v.id);
  try { await processVideo(v); db.prepare("UPDATE videos SET status='done' WHERE id=?").run(v.id); }
  catch (e) {
    console.error('Vidéo', v.id, e.message);
    db.prepare("UPDATE videos SET status='failed', error=? WHERE id=?").run('Échec de la création, réessayez.', v.id);
    db.prepare('UPDATE users SET used=MAX(0,used-1) WHERE id=?').run(v.user_id); // on rend le crédit
  }
  busy = false;
}, 3000);
// Les vidéos restées en cours après un arrêt du serveur sont relancées
db.prepare("UPDATE videos SET status='queued' WHERE status='processing'").run();

app.listen(PORT, () => console.log(`Marchéo : http://localhost:${PORT}`));
