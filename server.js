require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const telegram = require('./telegram');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './data/panel.db';
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const BOOT_TIME = Date.now();

/* ========================= DATABASE ========================= */
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS ovpn_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  label TEXT NOT NULL,
  quota_gb INTEGER DEFAULT 0,
  expiry_at TEXT,
  enabled INTEGER DEFAULT 1,
  cert_pem TEXT NOT NULL,
  key_pem TEXT NOT NULL,
  config_text TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
`);

const adminCount = db.prepare('SELECT COUNT(*) as c FROM admins').get().c;
if (adminCount === 0) {
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || 'admin123';
  db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)').run(username, bcrypt.hashSync(password, 10));
  console.log(`admin created -> username: ${username}`);
}

function getSetting(key, fallback) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : fallback;
}
function setSetting(key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, String(value));
}
function notify(text) { telegram.sendMessage(getSetting, text); }

function computeStatus(u) {
  if (!u.enabled) return 'disabled';
  if (u.expiry_at && new Date(u.expiry_at).getTime() < Date.now()) return 'expired';
  return 'active';
}
function serializeUser(u) {
  return {
    id: u.id, label: u.label,
    quota_gb: u.quota_gb, quota_fmt: u.quota_gb > 0 ? `${u.quota_gb} گیگ` : 'نامحدود',
    expiry_at: u.expiry_at, enabled: !!u.enabled,
    status: computeStatus(u),
    created_at: u.created_at,
  };
}

/* ========================= OpenVPN PKI (CA + Server + Clients) ========================= */
// همه‌ی گواهی‌ها (CA، سرور، کلاینت‌ها) اینجا با openssl و روی همین دیتابیس/دیسک پنل ساخته می‌شوند.
// این کار کاملاً روی Railway انجام می‌شود و نیازی به TUN ندارد چون فقط فایل تولید می‌کند، تونل برقرار نمی‌کند.
// وقتی یک VPS واقعی گرفتید، اسکریپت «/api/server-script» را از پنل دانلود و روی آن اجرا کنید — همان CA
// روی سرور هم نصب می‌شود، پس همه‌ی فایل‌های .ovpn که همین الان برای کاربران ساخته‌اید بی‌هیچ تغییری وصل خواهند شد.
const PKI_DIR = path.join(dataDir, 'ovpn-pki');

function ensureCA() {
  if (!fs.existsSync(PKI_DIR)) fs.mkdirSync(PKI_DIR, { recursive: true });
  const caKey = path.join(PKI_DIR, 'ca.key');
  const caCrt = path.join(PKI_DIR, 'ca.crt');
  if (!fs.existsSync(caKey) || !fs.existsSync(caCrt)) {
    execFileSync('openssl', ['genrsa', '-out', caKey, '2048']);
    execFileSync('openssl', ['req', '-x509', '-new', '-nodes', '-key', caKey, '-sha256', '-days', '3650',
      '-out', caCrt, '-subj', '/CN=OpenVPN-Panel-CA']);
  }
  return { caKey, caCrt };
}

function ensureServerCert() {
  const { caKey, caCrt } = ensureCA();
  const srvKey = path.join(PKI_DIR, 'server.key');
  const srvCsr = path.join(PKI_DIR, 'server.csr');
  const srvCrt = path.join(PKI_DIR, 'server.crt');
  const taKey = path.join(PKI_DIR, 'ta.key');
  const dhFile = path.join(PKI_DIR, 'dh.pem');
  if (!fs.existsSync(srvKey) || !fs.existsSync(srvCrt)) {
    execFileSync('openssl', ['genrsa', '-out', srvKey, '2048']);
    execFileSync('openssl', ['req', '-new', '-key', srvKey, '-out', srvCsr, '-subj', '/CN=openvpn-server']);
    execFileSync('openssl', ['x509', '-req', '-in', srvCsr, '-CA', caCrt, '-CAkey', caKey,
      '-CAcreateserial', '-out', srvCrt, '-days', '3650', '-sha256']);
    fs.unlinkSync(srvCsr);
  }
  if (!fs.existsSync(taKey)) {
    try { execFileSync('openvpn', ['--genkey', 'secret', taKey]); }
    catch { execFileSync('openssl', ['rand', '-hex', '256'], { stdio: ['ignore', fs.openSync(taKey, 'w'), 'ignore'] }); }
  }
  if (!fs.existsSync(dhFile)) {
    // پارامتر DH استاندارد RFC 7919 (ffdhe2048) — امن و بدون نیاز به تولید طولانی‌مدت با openssl dhparam
    fs.writeFileSync(dhFile, `-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----`);
  }
  return { caKey, caCrt, srvKey, srvCrt, taKey, dhFile };
}

function buildClientConfig(label) {
  const { caKey, caCrt } = ensureCA();
  const { taKey } = ensureServerCert();
  const safe = label.replace(/[^a-zA-Z0-9_-]/g, '_') + '_' + Date.now();
  const clientKey = path.join(PKI_DIR, `${safe}.key`);
  const clientCsr = path.join(PKI_DIR, `${safe}.csr`);
  const clientCrt = path.join(PKI_DIR, `${safe}.crt`);
  execFileSync('openssl', ['genrsa', '-out', clientKey, '2048']);
  execFileSync('openssl', ['req', '-new', '-key', clientKey, '-out', clientCsr, '-subj', `/CN=${safe}`]);
  execFileSync('openssl', ['x509', '-req', '-in', clientCsr, '-CA', caCrt, '-CAkey', caKey,
    '-CAcreateserial', '-out', clientCrt, '-days', '825', '-sha256']);
  const caPem = fs.readFileSync(caCrt, 'utf8').trim();
  const crtPem = fs.readFileSync(clientCrt, 'utf8').trim();
  const keyPem = fs.readFileSync(clientKey, 'utf8').trim();
  const taPem = fs.readFileSync(taKey, 'utf8').trim();
  fs.unlinkSync(clientCsr);

  const host = getSetting('server_host', '') || '<YOUR-VPS-IP>';
  const port = getSetting('server_port', '1194') || '1194';
  const proto = getSetting('server_proto', 'udp') || 'udp';

  const config_text = [
    'client', 'dev tun', `proto ${proto}`,
    `remote ${host} ${port}`,
    'resolv-retry infinite', 'nobind', 'persist-key', 'persist-tun',
    'remote-cert-tls server', 'cipher AES-256-GCM', 'auth SHA256', 'key-direction 1', 'verb 3',
    '<ca>', caPem, '</ca>',
    '<cert>', crtPem, '</cert>',
    '<key>', keyPem, '</key>',
    '<tls-auth>', taPem, '</tls-auth>',
  ].join('\n');
  return { cert_pem: crtPem, key_pem: keyPem, config_text };
}

// اسکریپت نصب خودکار سرور OpenVPN — روی هر Ubuntu/Debian VPS با روت اجرا شود.
// همان CA/سرور-سرتیفیکیت پنل را نصب می‌کند تا فایل‌های .ovpn که همین الان ساخته‌اید بدون تغییر وصل شوند.
function buildServerScript() {
  const { caCrt, srvKey, srvCrt, taKey, dhFile } = ensureServerCert();
  const caPem = fs.readFileSync(caCrt, 'utf8').trim();
  const srvKeyPem = fs.readFileSync(srvKey, 'utf8').trim();
  const srvCrtPem = fs.readFileSync(srvCrt, 'utf8').trim();
  const taPem = fs.readFileSync(taKey, 'utf8').trim();
  const dhPem = fs.readFileSync(dhFile, 'utf8').trim();
  const port = getSetting('server_port', '1194') || '1194';
  const proto = getSetting('server_proto', 'udp') || 'udp';

  return `#!/bin/bash
# نصب خودکار سرور OpenVPN — با CA همین پنل، تا کاربرهای ساخته‌شده الان بدون تغییر وصل شوند.
# اجرا روی یک VPS تازه (Ubuntu 22/24) با روت: sudo bash install-openvpn-server.sh
set -e
echo "== نصب پکیج‌ها =="
apt-get update -y
apt-get install -y openvpn iptables

mkdir -p /etc/openvpn/server
cat > /etc/openvpn/server/ca.crt <<'EOF'
${caPem}
EOF
cat > /etc/openvpn/server/server.crt <<'EOF'
${srvCrtPem}
EOF
cat > /etc/openvpn/server/server.key <<'EOF'
${srvKeyPem}
EOF
chmod 600 /etc/openvpn/server/server.key
cat > /etc/openvpn/server/ta.key <<'EOF'
${taPem}
EOF
cat > /etc/openvpn/server/dh.pem <<'EOF'
${dhPem}
EOF

cat > /etc/openvpn/server/server.conf <<EOF
port ${port}
proto ${proto}
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
key-direction 0
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
cipher AES-256-GCM
auth SHA256
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
explicit-exit-notify 1
EOF

echo "== فعال‌سازی IP forwarding =="
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn.conf
sysctl --system

echo "== تنظیم NAT (iptables) =="
IFACE=\\$(ip route | grep default | awk '{print \\$5}' | head -n1)
iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "\\$IFACE" -j MASQUERADE 2>/dev/null || \\
  iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "\\$IFACE" -j MASQUERADE
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent 2>/dev/null || true
netfilter-persistent save 2>/dev/null || true

echo "== باز کردن پورت در فایروال (در صورت فعال بودن ufw) =="
if command -v ufw >/dev/null 2>&1; then
  ufw allow ${port}/${proto} || true
fi

echo "== روشن کردن سرویس =="
systemctl enable --now openvpn-server@server

echo ""
echo "تمام شد. سرور OpenVPN روی پورت ${port}/${proto} فعال است."
echo "حالا در تنظیمات پنل، «آدرس سرور» را IP همین VPS بگذارید و کانفیگ‌های قبلی/جدید کاربران را بفرستید — بدون نیاز به ساخت مجدد."
`;
}

/* ========================= EXPRESS APP ========================= */
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: dataDir }),
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 3600 * 1000, sameSite: 'lax' },
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.status(401).json({ error: 'ابتدا وارد شوید' });
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username || '');
  if (!admin || !bcrypt.compareSync(password || '', admin.password_hash)) {
    return res.status(401).json({ error: 'یوزرنیم یا رمز عبور اشتباه است' });
  }
  req.session.adminId = admin.id;
  req.session.username = admin.username;
  res.json({ success: true });
});
app.post('/api/logout', (req, res) => { req.session.destroy(() => res.json({ success: true })); });
app.get('/api/me', (req, res) => {
  if (!req.session.adminId) return res.status(401).json({ error: 'unauthenticated' });
  res.json({ username: req.session.username });
});
app.post('/api/change-password', requireAuth, (req, res) => {
  const { current_password, new_password } = req.body || {};
  const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(req.session.adminId);
  if (!bcrypt.compareSync(current_password || '', admin.password_hash)) return res.status(400).json({ error: 'رمز فعلی اشتباه است' });
  if (!new_password || new_password.length < 6) return res.status(400).json({ error: 'رمز جدید باید حداقل ۶ کاراکتر باشد' });
  db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(new_password, 10), admin.id);
  res.json({ success: true });
});

app.get('/api/settings', requireAuth, (req, res) => {
  res.json({
    server_host: getSetting('server_host', ''),
    server_port: getSetting('server_port', '1194'),
    server_proto: getSetting('server_proto', 'udp'),
    telegram_bot_token: getSetting('telegram_bot_token', ''),
    telegram_chat_id: getSetting('telegram_chat_id', ''),
    telegram_notify: getSetting('telegram_notify', '1') === '1',
  });
});
app.post('/api/settings', requireAuth, (req, res) => {
  const { server_host, server_port, server_proto } = req.body || {};
  if (server_host !== undefined) setSetting('server_host', server_host.trim());
  if (server_port !== undefined) setSetting('server_port', server_port.trim() || '1194');
  if (server_proto !== undefined) setSetting('server_proto', server_proto);
  res.json({ success: true });
});
app.post('/api/telegram-settings', requireAuth, (req, res) => {
  const { telegram_bot_token, telegram_chat_id, telegram_notify } = req.body || {};
  if (telegram_bot_token !== undefined) setSetting('telegram_bot_token', telegram_bot_token.trim());
  if (telegram_chat_id !== undefined) setSetting('telegram_chat_id', telegram_chat_id.trim());
  setSetting('telegram_notify', telegram_notify ? '1' : '0');
  telegram.startPolling(getSetting, { onMessage: handleTelegramCommand });
  res.json({ success: true });
});

app.get('/api/system/info', requireAuth, (req, res) => {
  res.json({
    uptime_sec: Math.floor((Date.now() - BOOT_TIME) / 1000),
    platform: os.platform(), arch: os.arch(),
    load: os.loadavg(), freemem: os.freemem(), totalmem: os.totalmem(),
  });
});

app.get('/api/users', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM ovpn_users ORDER BY id DESC').all();
  res.json(rows.map(serializeUser));
});
app.post('/api/users', requireAuth, (req, res) => {
  try {
    const { label, quota_gb, expiry_days } = req.body || {};
    if (!label || !label.trim()) return res.status(400).json({ error: 'نام کاربر لازم است' });
    const built = buildClientConfig(label.trim());
    const expiryAt = Number(expiry_days) > 0 ? new Date(Date.now() + Number(expiry_days) * 86400000).toISOString() : null;
    const info = db.prepare(`INSERT INTO ovpn_users (label, quota_gb, expiry_at, enabled, cert_pem, key_pem, config_text)
      VALUES (?, ?, ?, 1, ?, ?, ?)`).run(label.trim(), Number(quota_gb) || 0, expiryAt, built.cert_pem, built.key_pem, built.config_text);
    const row = db.prepare('SELECT * FROM ovpn_users WHERE id = ?').get(info.lastInsertRowid);
    notify(`🔐 <b>کاربر OpenVPN جدید</b>\nنام: «${label.trim()}»\nحجم: ${Number(quota_gb) > 0 ? quota_gb + ' گیگ' : 'نامحدود'}`);
    res.json(serializeUser(row));
  } catch (e) {
    res.status(500).json({ error: 'ساخت کاربر ناموفق بود: ' + e.message + ' (مطمئن شوید openssl روی سرور نصب است)' });
  }
});
app.post('/api/users/:id/toggle', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM ovpn_users WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'یافت نشد' });
  db.prepare('UPDATE ovpn_users SET enabled = ? WHERE id = ?').run(row.enabled ? 0 : 1, row.id);
  res.json(serializeUser(db.prepare('SELECT * FROM ovpn_users WHERE id = ?').get(row.id)));
});
app.post('/api/users/:id/renew', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM ovpn_users WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'یافت نشد' });
  const days = Number((req.body || {}).days) || 30;
  const base = row.expiry_at && new Date(row.expiry_at).getTime() > Date.now() ? new Date(row.expiry_at).getTime() : Date.now();
  const newExpiry = new Date(base + days * 86400000).toISOString();
  db.prepare('UPDATE ovpn_users SET expiry_at = ?, enabled = 1 WHERE id = ?').run(newExpiry, row.id);
  res.json(serializeUser(db.prepare('SELECT * FROM ovpn_users WHERE id = ?').get(row.id)));
});
app.delete('/api/users/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM ovpn_users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});
app.get('/api/users/:id/download', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM ovpn_users WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send('not found');
  res.setHeader('Content-Disposition', `attachment; filename="${row.label.replace(/[^a-zA-Z0-9_-]/g, '_')}.ovpn"`);
  res.send(row.config_text);
});

app.get('/api/server-script', requireAuth, (req, res) => {
  try {
    const script = buildServerScript();
    res.setHeader('Content-Disposition', 'attachment; filename="install-openvpn-server.sh"');
    res.send(script);
  } catch (e) {
    res.status(500).json({ error: 'ساخت اسکریپت ناموفق بود: ' + e.message });
  }
});

app.get('/api/backup', requireAuth, (req, res) => {
  res.setHeader('Content-Disposition', 'attachment; filename="panel-backup.db"');
  res.sendFile(path.resolve(DB_PATH));
});

app.post('/api/telegram/test', requireAuth, async (req, res) => {
  const r = await telegram.sendMessage(getSetting, '✅ این یک پیام تست از پنل OpenVPN است. ربات به‌درستی متصل است.');
  res.json({ result: r });
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.get(['/', '/index.html', '/dashboard.html'], (req, res) => {
  if (!req.session.adminId) return res.redirect('/login.html');
  res.send(DASHBOARD_HTML);
});
app.get('/login.html', (req, res) => res.send(LOGIN_HTML));

/* ========================= TELEGRAM BOT COMMANDS ========================= */
async function handleTelegramCommand(text, reply) {
  const [cmd, ...args] = text.split(/\s+/);
  if (cmd === '/start' || cmd === '/help') {
    return reply('دستورات:\n/status - وضعیت پنل\n/list - لیست کاربران\n/add نام حجم(GB) روز - ساخت کاربر (مثال: /add ali 30 30)\n/on شناسه - فعال کردن\n/off شناسه - غیرفعال کردن\n/del شناسه - حذف کاربر');
  }
  if (cmd === '/status') {
    const c = db.prepare('SELECT COUNT(*) c FROM ovpn_users').get().c;
    const active = db.prepare('SELECT COUNT(*) c FROM ovpn_users WHERE enabled=1').get().c;
    return reply(`📊 وضعیت پنل\nکل کاربران: ${c}\nفعال: ${active}\nآپتایم: ${Math.floor((Date.now() - BOOT_TIME) / 60000)} دقیقه`);
  }
  if (cmd === '/list') {
    const rows = db.prepare('SELECT * FROM ovpn_users ORDER BY id DESC LIMIT 30').all();
    if (!rows.length) return reply('هنوز کاربری ساخته نشده.');
    return reply(rows.map(u => `#${u.id} «${u.label}» — ${computeStatus(u)}`).join('\n'));
  }
  if (cmd === '/add') {
    const [label, quota, days] = args;
    if (!label) return reply('فرمت درست: /add نام حجم روز\nمثال: /add ali 30 30');
    try {
      const built = buildClientConfig(label);
      const expiryAt = Number(days) > 0 ? new Date(Date.now() + Number(days) * 86400000).toISOString() : null;
      const info = db.prepare(`INSERT INTO ovpn_users (label, quota_gb, expiry_at, enabled, cert_pem, key_pem, config_text)
        VALUES (?, ?, ?, 1, ?, ?, ?)`).run(label, Number(quota) || 0, expiryAt, built.cert_pem, built.key_pem, built.config_text);
      await reply(`✅ کاربر «${label}» با شناسه #${info.lastInsertRowid} ساخته شد.`);
      await telegram.sendDocument(getSetting, `${label}.ovpn`, built.config_text, `کانفیگ OpenVPN برای «${label}»`);
    } catch (e) { return reply('خطا: ' + e.message); }
    return;
  }
  if (cmd === '/on' || cmd === '/off') {
    const id = Number(args[0]);
    const row = db.prepare('SELECT * FROM ovpn_users WHERE id = ?').get(id);
    if (!row) return reply('کاربری با این شناسه پیدا نشد.');
    db.prepare('UPDATE ovpn_users SET enabled = ? WHERE id = ?').run(cmd === '/on' ? 1 : 0, id);
    return reply(`کاربر #${id} ${cmd === '/on' ? 'فعال' : 'غیرفعال'} شد.`);
  }
  if (cmd === '/del') {
    const id = Number(args[0]);
    db.prepare('DELETE FROM ovpn_users WHERE id = ?').run(id);
    return reply(`کاربر #${id} حذف شد.`);
  }
}
telegram.startPolling(getSetting, { onMessage: handleTelegramCommand });

// چک دوره‌ای انقضا — هر ۵ دقیقه، برای اعلان به تلگرام وقتی کاربری تازه منقضی می‌شود
setInterval(() => {
  const rows = db.prepare("SELECT * FROM ovpn_users WHERE enabled = 1 AND expiry_at IS NOT NULL").all();
  for (const u of rows) {
    if (new Date(u.expiry_at).getTime() < Date.now()) {
      notify(`⏰ کاربر «${u.label}» منقضی شد.`);
    }
  }
}, 5 * 60 * 1000);

/* ========================= HTML ========================= */
const STYLE = `
:root{--bg:#0b1220;--bg-panel:#111a2e;--bg-card:#152037;--border:#22304d;--text:#dbe4f3;--text-dim:#7d8bab;--accent:#39d5c9;--danger:#ef5a6f;--warn:#e8b04b;--ok:#3ecf8e;--mono:"SFMono-Regular",Consolas,monospace;--sans:"Vazirmatn","Inter",system-ui,sans-serif;}
*{box-sizing:border-box;}html,body{margin:0;padding:0;}
body{background:radial-gradient(circle at 15% 0%,#12335533 0%,transparent 45%),var(--bg);color:var(--text);font-family:var(--sans);direction:rtl;min-height:100vh;}
a{color:var(--accent);text-decoration:none;}
.wrap-center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
.login-card{width:100%;max-width:380px;background:var(--bg-panel);border:1px solid var(--border);border-radius:14px;padding:32px;position:relative;overflow:hidden;}
.login-card::before{content:"";position:absolute;top:0;right:0;left:0;height:3px;background:linear-gradient(90deg,var(--accent),transparent 70%);}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:6px;}
.brand .dot{width:10px;height:10px;border-radius:50%;background:var(--accent);box-shadow:0 0 12px var(--accent);}
.brand h1{font-size:18px;margin:0;font-weight:700;letter-spacing:.3px;}
.sub{color:var(--text-dim);font-size:13px;margin:0 0 24px;}
label{display:block;font-size:12px;color:var(--text-dim);margin:14px 0 6px;}
input,select{width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--border);background:#0d1526;color:var(--text);font-family:var(--sans);font-size:14px;}
input:focus,select:focus{outline:none;border-color:var(--accent);}
button{cursor:pointer;border:none;border-radius:8px;font-family:var(--sans);font-weight:600;font-size:14px;}
.btn-primary{width:100%;padding:11px;margin-top:20px;background:var(--accent);color:#04231f;}
.btn-primary:hover{background:#4fe0d4;}
.btn-secondary{padding:8px 14px;background:transparent;color:var(--text);border:1px solid var(--border);}
.btn-secondary:hover{border-color:var(--accent);color:var(--accent);}
.btn-danger{padding:8px 14px;background:#2a1620;color:var(--danger);border:1px solid #4a2230;}
.btn-danger:hover{background:var(--danger);color:#2a0810;}
.btn-sm{padding:6px 10px;font-size:12px;border-radius:6px;}
.err{margin-top:14px;padding:10px 12px;border-radius:8px;background:#2a1620;color:var(--danger);font-size:13px;display:none;}
.warn-box{margin-bottom:18px;padding:12px 14px;border-radius:8px;background:#2a2410;color:var(--warn);font-size:13px;border:1px solid #4a3a10;}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:16px 28px;border-bottom:1px solid var(--border);background:var(--bg-panel);position:sticky;top:0;z-index:5;flex-wrap:wrap;gap:10px;}
.user-chip{display:flex;align-items:center;gap:12px;font-size:13px;color:var(--text-dim);flex-wrap:wrap;}
.container{max-width:1000px;margin:0 auto;padding:28px;}
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:28px;}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:16px;}
.stat-card .num{font-family:var(--mono);font-size:22px;font-weight:700;}
.stat-card .label{color:var(--text-dim);font-size:11px;margin-top:4px;}
.section-head{display:flex;align-items:center;justify-content:space-between;margin:32px 0 14px;flex-wrap:wrap;gap:10px;}
.section-head h2{font-size:15px;margin:0;color:var(--text);}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:14px;}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;white-space:nowrap;}
.badge-ok{background:#0e2a1f;color:var(--ok);}
.badge-bad{background:#2a1620;color:var(--danger);}
.badge-warn{background:#2a2410;color:var(--warn);}
.user-card{display:flex;flex-direction:column;gap:10px;padding:16px;}
.user-top{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap;}
.user-name{font-weight:700;font-size:14px;}
.user-meta{color:var(--text-dim);font-size:11px;font-family:var(--mono);}
.actions{display:flex;gap:6px;flex-wrap:wrap;}
.empty-hint{color:var(--text-dim);font-size:13px;padding:20px;text-align:center;}
.modal-backdrop{position:fixed;inset:0;background:#02050ccc;display:none;align-items:center;justify-content:center;z-index:50;padding:20px;}
.modal{background:var(--bg-panel);border:1px solid var(--border);border-radius:14px;padding:26px;width:100%;max-width:480px;max-height:88vh;overflow:auto;}
.modal h3{margin-top:0;}
.modal-close{float:left;cursor:pointer;color:var(--text-dim);font-size:20px;}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--bg-card);border:1px solid var(--accent);color:var(--text);padding:10px 18px;border-radius:8px;font-size:13px;z-index:100;display:none;max-width:90vw;}
.toast.error{border-color:var(--danger);}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
`;

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ورود | پنل OpenVPN</title><style>${STYLE}</style></head>
<body>
<div class="wrap-center">
  <form class="login-card" id="loginForm">
    <div class="brand"><span class="dot"></span><h1>پنل OpenVPN</h1></div>
    <p class="sub">مدیریت کاربران و کانفیگ‌های OpenVPN</p>
    <label>نام کاربری</label><input type="text" name="username" required autofocus>
    <label>رمز عبور</label><input type="password" name="password" required>
    <button class="btn-primary" type="submit">ورود</button>
    <div class="err" id="errBox"></div>
  </form>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errBox = document.getElementById('errBox'); errBox.style.display = 'none';
  const fd = new FormData(e.target);
  try {
    const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ username: fd.get('username'), password: fd.get('password') }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'خطا در ورود');
    window.location.href = '/dashboard.html';
  } catch (err) { errBox.textContent = err.message; errBox.style.display = 'block'; }
});
</script>
</body></html>`;

function statusFa(s) { return { active: 'فعال', disabled: 'غیرفعال', expired: 'منقضی' }[s] || s; }

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>داشبورد | پنل OpenVPN</title><style>${STYLE}</style></head>
<body>
<div class="topbar">
  <div class="brand"><span class="dot"></span><h1 style="font-size:16px;margin:0;">پنل OpenVPN</h1></div>
  <div class="user-chip"><span id="whoami">...</span>
    <a class="btn-secondary btn-sm" href="/api/backup" style="display:inline-block">دانلود بکاپ</a>
    <button class="btn-secondary btn-sm" id="btnChangePass">تغییر رمز</button>
    <button class="btn-danger btn-sm" id="btnLogout">خروج</button>
  </div>
</div>
<div class="container">

  <div id="hostWarn" class="warn-box" style="display:none">
    ⚠️ هنوز روی هیچ VPS واقعی نصب نشده‌اید — کانفیگ‌هایی که می‌سازید وصل نمی‌شوند تا وقتی اسکریپت سرور را (پایین صفحه) روی یک VPS اجرا کنید و آدرس آن را اینجا ثبت کنید.
  </div>

  <div class="stats-row">
    <div class="stat-card"><div class="num" id="statUsers">0</div><div class="label">کل کاربران</div></div>
    <div class="stat-card"><div class="num" id="statActive">0</div><div class="label">فعال</div></div>
    <div class="stat-card"><span class="badge" id="statHost"><span class="dot"></span>...</span><div class="label" style="margin-top:8px;">آدرس سرور</div></div>
  </div>

  <div class="section-head">
    <h2>کاربران OpenVPN</h2>
    <div class="actions"><button class="btn-primary" style="width:auto;padding:9px 16px;margin:0" id="btnAddUser">+ ساخت کاربر</button></div>
  </div>
  <div id="usersList"></div>
  <div id="usersEmptyHint" class="card empty-hint" style="display:none">هنوز کاربری ساخته نشده</div>

  <div class="section-head"><h2>تنظیمات سرور</h2></div>
  <div class="card">
    <p class="sub" style="margin-top:0">این آدرس داخل فایل‌های .ovpn که از این پس می‌سازید نوشته می‌شود (کانفیگ‌های قبلی تغییر نمی‌کنند، باید دوباره دانلود شوند).</p>
    <form id="formSettings">
      <div class="grid2">
        <div><label>آدرس/IP سرور OpenVPN</label><input name="server_host" placeholder="1.2.3.4"></div>
        <div><label>پورت</label><input name="server_port" placeholder="1194"></div>
      </div>
      <label>پروتکل</label>
      <select name="server_proto"><option value="udp">UDP</option><option value="tcp">TCP</option></select>
      <button class="btn-primary" type="submit">ذخیره</button>
      <div class="err" id="settingsErr"></div>
    </form>
  </div>

  <div class="section-head"><h2>نصب خودکار سرور (وقتی VPS گرفتید)</h2></div>
  <div class="card">
    <p class="sub" style="margin-top:0">وقتی یک VPS (Ubuntu/Debian) با دسترسی روت گرفتید، این اسکریپت را دانلود کن، به سرور آپلود کن و با <code>sudo bash install-openvpn-server.sh</code> اجرا کن. همان گواهی CA پنل رویش نصب می‌شود، پس همه‌ی کاربرهایی که همین الان ساخته‌اید بدون نیاز به ساخت دوباره وصل خواهند شد — فقط بعدش آدرس سرور را بالا ثبت کن و کانفیگ‌ها را دوباره دانلود/ارسال کن.</p>
    <a class="btn-secondary" href="/api/server-script" style="display:inline-block">دانلود install-openvpn-server.sh</a>
  </div>

  <div class="section-head"><h2>ربات تلگرام (اعلان‌ها و کنترل از راه دور)</h2></div>
  <div class="card">
    <p class="sub" style="margin-top:0">با ساخت ربات از <a href="https://t.me/BotFather" target="_blank">BotFather@</a> توکن را اینجا وارد کنید، سپس در تلگرام برای ربات خودتان /start بفرستید تا آیدی چت را بگیرید.</p>
    <form id="formTelegram">
      <label>توکن ربات</label><input name="telegram_bot_token" placeholder="123456:ABC-...">
      <label>آیدی چت (Chat ID)</label><input name="telegram_chat_id" placeholder="مثلا 123456789">
      <label style="display:flex;align-items:center;gap:8px;margin-top:16px;">
        <input type="checkbox" name="telegram_notify" style="width:auto" checked> فعال بودن اعلان‌های خودکار
      </label>
      <div class="grid2" style="margin-top:16px">
        <button class="btn-primary" type="submit" style="margin-top:0">ذخیره</button>
        <button class="btn-secondary" type="button" id="btnTestTelegram" style="margin-top:0">ارسال پیام تست</button>
      </div>
      <div class="err" id="telegramErr"></div>
    </form>
  </div>

</div>

<div class="modal-backdrop" id="modalAddUser"><div class="modal">
  <span class="modal-close" data-close>&times;</span><h3>ساخت کاربر OpenVPN</h3>
  <form id="formAddUser">
    <label>نام دلخواه کاربر</label><input name="label" placeholder="مثلا: علی-گوشی" required>
    <div class="grid2">
      <div><label>سقف حجم (GB) — اطلاعاتی، صفر=نامحدود</label><input name="quota_gb" type="number" value="0"></div>
      <div><label>مدت اعتبار (روز) — صفر=نامحدود</label><input name="expiry_days" type="number" value="30"></div>
    </div>
    <button class="btn-primary" type="submit">ساخت و دانلود</button>
    <div class="err" id="addUserErr"></div>
  </form>
</div></div>

<div class="modal-backdrop" id="modalChangePass"><div class="modal">
  <span class="modal-close" data-close>&times;</span><h3>تغییر رمز عبور</h3>
  <form id="formChangePass">
    <label>رمز فعلی</label><input name="current_password" type="password" required>
    <label>رمز جدید</label><input name="new_password" type="password" required minlength="6">
    <button class="btn-primary" type="submit">تغییر رمز</button>
    <div class="err" id="changePassErr"></div>
  </form>
</div></div>

<div class="toast" id="toast"></div>

<script>
function toast(msg, isError=false){ const t=document.getElementById('toast'); t.textContent=msg; t.className='toast'+(isError?' error':''); t.style.display='block'; setTimeout(()=>t.style.display='none',3500); }
function openModal(id){ document.getElementById(id).style.display='flex'; }
function closeModal(id){ document.getElementById(id).style.display='none'; }
function escapeHtml(str){ return String(str).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
function statusLabel(s){ return {active:'فعال', disabled:'غیرفعال', expired:'منقضی'}[s] || s; }
function statusBadgeClass(s){ return {active:'badge-ok', disabled:'badge-bad', expired:'badge-warn'}[s] || 'badge-bad'; }
document.querySelectorAll('[data-close]').forEach(el => el.addEventListener('click', (e) => closeModal(e.target.closest('.modal-backdrop').id)));

async function loadMe(){
  const res = await fetch('/api/me');
  if (!res.ok) { window.location.href = '/login.html'; return; }
  const data = await res.json();
  document.getElementById('whoami').textContent = data.username;
}
async function loadSettings(){
  const res = await fetch('/api/settings');
  const s = await res.json();
  const f = document.getElementById('formSettings');
  f.server_host.value = s.server_host; f.server_port.value = s.server_port; f.server_proto.value = s.server_proto;
  document.getElementById('formTelegram').telegram_bot_token.value = s.telegram_bot_token;
  document.getElementById('formTelegram').telegram_chat_id.value = s.telegram_chat_id;
  document.getElementById('formTelegram').telegram_notify.checked = s.telegram_notify;
  document.getElementById('statHost').innerHTML = s.server_host ? ('<span class="dot"></span>' + escapeHtml(s.server_host)) : 'تنظیم نشده';
  document.getElementById('hostWarn').style.display = s.server_host ? 'none' : 'block';
}
async function loadUsers(){
  const res = await fetch('/api/users');
  const rows = await res.json();
  document.getElementById('statUsers').textContent = rows.length;
  document.getElementById('statActive').textContent = rows.filter(u=>u.status==='active').length;
  const list = document.getElementById('usersList');
  document.getElementById('usersEmptyHint').style.display = rows.length ? 'none':'block';
  list.innerHTML = rows.map(u => \`
    <div class="card user-card">
      <div class="user-top">
        <div>
          <div class="user-name">\${escapeHtml(u.label)}</div>
          <div class="user-meta">#\${u.id} — حجم: \${u.quota_fmt} — انقضا: \${u.expiry_at ? new Date(u.expiry_at).toLocaleDateString('fa-IR') : 'نامحدود'}</div>
        </div>
        <span class="badge \${statusBadgeClass(u.status)}"><span class="dot"></span>\${statusLabel(u.status)}</span>
      </div>
      <div class="actions">
        <a class="btn-secondary btn-sm" href="/api/users/\${u.id}/download">دانلود .ovpn</a>
        <button class="btn-secondary btn-sm" onclick="toggleUser(\${u.id})">\${u.enabled ? 'غیرفعال کن' : 'فعال کن'}</button>
        <button class="btn-secondary btn-sm" onclick="renewUser(\${u.id})">تمدید ۳۰ روز</button>
        <button class="btn-danger btn-sm" onclick="deleteUser(\${u.id})">حذف</button>
      </div>
    </div>\`).join('');
}
async function toggleUser(id){ await fetch(\`/api/users/\${id}/toggle\`, {method:'POST'}); loadUsers(); }
async function renewUser(id){ await fetch(\`/api/users/\${id}/renew\`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({days:30})}); toast('تمدید شد'); loadUsers(); }
async function deleteUser(id){ if(!confirm('حذف شود؟')) return; await fetch(\`/api/users/\${id}\`, {method:'DELETE'}); loadUsers(); }

document.getElementById('btnAddUser').addEventListener('click', () => openModal('modalAddUser'));
document.getElementById('formAddUser').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errBox = document.getElementById('addUserErr'); errBox.style.display='none';
  const fd = new FormData(e.target);
  try {
    const res = await fetch('/api/users', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ label: fd.get('label'), quota_gb: fd.get('quota_gb'), expiry_days: fd.get('expiry_days') }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'خطا');
    closeModal('modalAddUser'); e.target.reset(); toast('کاربر ساخته شد'); await loadUsers();
    window.location.href = \`/api/users/\${data.id}/download\`;
  } catch (err) { errBox.textContent = err.message; errBox.style.display='block'; }
});

document.getElementById('formSettings').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errBox = document.getElementById('settingsErr'); errBox.style.display='none';
  const fd = new FormData(e.target);
  try {
    const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ server_host: fd.get('server_host'), server_port: fd.get('server_port'), server_proto: fd.get('server_proto') }) });
    if (!res.ok) throw new Error((await res.json()).error || 'خطا');
    toast('ذخیره شد'); await loadSettings();
  } catch (err) { errBox.textContent = err.message; errBox.style.display='block'; }
});

document.getElementById('formTelegram').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errBox = document.getElementById('telegramErr'); errBox.style.display='none';
  const fd = new FormData(e.target);
  try {
    const res = await fetch('/api/telegram-settings', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ telegram_bot_token: fd.get('telegram_bot_token'), telegram_chat_id: fd.get('telegram_chat_id'), telegram_notify: fd.get('telegram_notify') === 'on' }) });
    if (!res.ok) throw new Error((await res.json()).error || 'خطا');
    toast('ذخیره شد');
  } catch (err) { errBox.textContent = err.message; errBox.style.display='block'; }
});
document.getElementById('btnTestTelegram').addEventListener('click', async () => {
  const res = await fetch('/api/telegram/test', {method:'POST'});
  const data = await res.json();
  toast(data.result && data.result.skipped ? 'ابتدا توکن و چت آیدی را ذخیره کنید' : 'پیام تست ارسال شد');
});

document.getElementById('btnChangePass').addEventListener('click', () => openModal('modalChangePass'));
document.getElementById('formChangePass').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errBox = document.getElementById('changePassErr'); errBox.style.display='none';
  const fd = new FormData(e.target);
  try {
    const res = await fetch('/api/change-password', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ current_password: fd.get('current_password'), new_password: fd.get('new_password') }) });
    if (!res.ok) throw new Error((await res.json()).error || 'خطا');
    closeModal('modalChangePass'); e.target.reset(); toast('رمز تغییر کرد');
  } catch (err) { errBox.textContent = err.message; errBox.style.display='block'; }
});
document.getElementById('btnLogout').addEventListener('click', async () => { await fetch('/api/logout', {method:'POST'}); window.location.href='/login.html'; });

loadMe(); loadSettings(); loadUsers();
</script>
</body></html>`;

app.listen(PORT, () => console.log(`OpenVPN panel running on port ${PORT}`));
