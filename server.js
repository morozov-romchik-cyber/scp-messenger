require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Server } = require('socket.io');

// #SECTION: S3_IMPORTS
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// #SECTION: S3_CONFIGURATION (ВАШИ КЛЮЧИ)
const S3_ENDPOINT = process.env.S3_ENDPOINT || 'https://firsts3.ru';
const S3_BUCKET = process.env.S3_BUCKET || 'scp-messenger';
const S3_REGION = process.env.S3_REGION || 'default';
// Вставьте сюда ваши Access Key и Secret Key от FirstVDS
const S3_ACCESS_KEY = process.env.S3_ACCESS_KEY || '5N9ER3SW21Z8MXWG75DJ';
const S3_SECRET_KEY = process.env.S3_SECRET_KEY || 'n01UxvY1IsuUEmY1vBx8Eu2yXPKpW05r6dzBI5Q9';

const s3 = new S3Client({
  endpoint: S3_ENDPOINT,
  region: S3_REGION,
  credentials: {
    accessKeyId: S3_ACCESS_KEY,
    secretAccessKey: S3_SECRET_KEY
  },
  forcePathStyle: true
});

const serverLog = (type, text) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [${type.toUpperCase()}] ${text}`);
};

process.on('uncaughtException', (err) => serverLog('error', 'Поймана необработанная ошибка: ' + err.stack));
process.on('unhandledRejection', (err) => serverLog('error', 'Необработанный промис: ' + err));

const ALLOWED_EXT = new Set([
  '.ai', '.all', '.apk', '.accdb', '.asm', '.app', '.arj', '.avi', '.bak', '.bat', 
  '.bin', '.bmp', '.bz2', '.c', '.cab', '.cc', '.cfg', '.class', '.cmd', '.conf', 
  '.cpl', '.cpp', '.crt', '.cs', '.css', '.csv', '.dae', '.dat', '.db', '.dbf', 
  '.dmp', '.doc', '.docx', '.dll', '.elf', '.et', '.etl', '.evtx', '.exe', '.flac', 
  '.frm', '.fw', '.gif', '.glb', '.gltf', '.go', '.gz', '.h', '.heic', '.hex', 
  '.hpp', '.htm', '.html', '.ibd', '.ico', '.icns', '.img', '.ini', '.iso', '.java', 
  '.jpeg', '.jpg', '.js', '.json', '.jons', '.key', '.ldf', '.lnk', '.log', '.lua', 
  '.m4a', '.manifest', '.mb', '.md', '.mdb', '.mdf', '.mkv', '.mov', '.mp3', '.mp4', 
  '.mpeg', '.mpg', '.msi', '.msp', '.mui', '.odt', '.ogg', '.old', '.ocx', '.ova', 
  '.ovf', '.ovpn', '.pas', '.pcap', '.pcapng', '.pdb', '.pdf', '.pem', '.pf', '.php', 
  '.p12', '.pfx', '.png', '.ppt', '.pptx', '.ps', '.py', '.pyc', '.qcow2', '.rar', '.raw', '.reg', 
  '.res', '.resources', '.rom', '.rtf', '.rs', '.scr', '.s', '.7z', '.sh', '.sql', 
  '.sqlite', '.sqlite3', '.svg', '.sys', '.tar', '.tif', '.tiff', '.tmp', '.ts', 
  '.url', '.var', '.vb', '.vdi', '.vhd', '.vhdx', '.vmdk', '.wav', '.webm', '.webp', 
  '.wma', '.wmv', '.xls', '.xlsx', '.xml', '.xpi', '.xz', '.yaml', '.yml', '.zip', '.zst', '.torrent'
]);

const ROLE_RANK = { user: 1, helper: 2, moderator: 3, admin: 4, sysadmin: 5 };
const ROLE_LABEL = { user: 'Пользователь', helper: 'Хелпер', moderator: 'Модератор', admin: 'Админ', sysadmin: 'SysAdmin' };

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const DB_FILE = path.join(__dirname, 'scp-db.json');
let db = { users: [], recovery_codes: [], chats: [], chat_members: [], messages: [], attachments: [], blocks: [], banned_ips: [], invite_codes: [] };

// #SECTION: DB_SYNC_TO_S3_QUEUE (Фоновая синхронизация)
let isS3Syncing = false;
let pendingS3Sync = false;

const saveDb = () => {
  try {
    // 1. Мгновенно сохраняем локально (для скорости работы)
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));

    // 2. Отправляем в облако S3 (в фоне, чтобы не тормозить сервер)
    if (isS3Syncing) {
      pendingS3Sync = true;
      return;
    }

    const upload = async () => {
      isS3Syncing = true;
      try {
        await s3.send(new PutObjectCommand({
          Bucket: S3_BUCKET,
          Key: 'database/scp-db.json',
          Body: JSON.stringify(db, null, 2),
          ContentType: 'application/json'
        }));
        serverLog('info', 'База данных успешно сохранена в S3');
      } catch (err) {
        serverLog('error', 'Ошибка сохранения БД в S3: ' + err.message);
      }
      isS3Syncing = false;

      if (pendingS3Sync) {
        pendingS3Sync = false;
        upload();
      }
    };
    upload();
  } catch (e) {
    serverLog('error', 'Ошибка локальной записи БД: ' + e.message);
  }
};

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

server.requestTimeout = 0;
server.headersTimeout = 0;
server.timeout = 0;

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => { res.sendFile(path.join(process.cwd(), 'public', 'index.html')); });
app.use('/uploads', express.static(UPLOAD_DIR));

const genId = () => crypto.randomBytes(12).toString('hex');
const signToken = (userId) => jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '30d' });
const publicUser = (u) => ({
  id: u.id, username: u.username, displayName: u.display_name, avatarUrl: u.avatar_url,
  status: u.status, level: u.level || 1, read_deleted: u.read_deleted || false,
  ip: u.ip || 'Скрыт', role: u.role || 'user', invited_by: u.invited_by || null,
  ban_expires: u.ban_expires || 0
});

const getRealIp = (req) => {
  let ip = req.headers['cf-connecting-ip'] ||
           (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : req.socket.remoteAddress) ||
           'unknown';
  return ip.replace('::ffff:', '');
};

const decodeFilename = (name) => {
  if (!name) return name;
  if (/[^\x00-\xFF]/.test(name)) return name;
  try {
    const decoded = Buffer.from(name, 'latin1').toString('utf8');
    if (decoded.includes('\uFFFD')) return name;
    return decoded;
  } catch (e) { return name; }
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const originalName = decodeFilename(file.originalname);
    const ext = path.extname(originalName).toLowerCase();
    cb(null, genId() + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const originalName = decodeFilename(file.originalname);
    const ext = path.extname(originalName).toLowerCase();
    if (!ALLOWED_EXT.has(ext)) return cb(new Error('Недопустимый тип файла: ' + ext));
    cb(null, true);
  }
});
const uploadSingle = (field) => (req, res, next) => {
  upload.single(field)(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || 'Ошибка загрузки' });
    next();
  });
};

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;

    const user = db.users.find(u => u.id === req.userId);
    if (user && user.ban_expires && user.ban_expires !== 0) {
      const now = Date.now();
      if (user.ban_expires === -1 || user.ban_expires > now) {
        return res.status(403).json({ error: 'BANNED', ban_expires: user.ban_expires });
      } else {
        user.ban_expires = 0;
        saveDb();
      }
    }
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function emitToChatMembers(chatId, event, payload) {
  const members = db.chat_members.filter(m => m.chat_id === chatId);
  members.forEach(m => io.to(`user:${m.user_id}`).emit(event, payload));
}

const findUserByUsername = (username) => {
  const cleanName = String(username || '').trim().replace(/^@/, '').toLowerCase();
  return db.users.find(u => u.username.toLowerCase() === cleanName);
};

const chatIsBlocked = (chatId, myId) => {
  const members = db.chat_members.filter(m => m.chat_id === chatId);
  const otherId = members.find(m => m.user_id !== myId)?.user_id;
  if (!otherId) return false;
  return db.blocks.some(b => (b.blocker === myId && b.blocked === otherId) || (b.blocker === otherId && b.blocked === myId));
};

// ================= ADMIN =================
app.post('/api/admin/ban-user', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  const { username, duration } = req.body;
  const target = findUserByUsername(username);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.role === 'sysadmin') return res.status(403).json({ error: 'НЕЛЬЗЯ забанить системного администратора (SysAdmin)!' });
  if (target.role === 'admin' && me.role !== 'sysadmin') return res.status(403).json({ error: 'Только SysAdmin может банить админов' });
  if (target.id === me.id) return res.status(400).json({ error: 'Нельзя забанить себя' });
  const numDuration = Number(duration);
  if (isNaN(numDuration)) return res.status(400).json({ error: 'Неверно указано время бана' });
  if (numDuration === 0) target.ban_expires = 0;
  else if (numDuration === -1) target.ban_expires = -1;
  else target.ban_expires = Date.now() + numDuration * 60 * 1000;
  saveDb();
  if (target.ban_expires !== 0) io.to(`user:${target.id}`).emit('forceLogout', { ban_expires: target.ban_expires });
  io.emit('refreshData');
  res.json({ ok: true, ban_expires: target.ban_expires });
});

app.post('/api/admin/delete-user', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  const { username } = req.body;
  const target = findUserByUsername(username);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.role === 'sysadmin') return res.status(400).json({ error: 'Нельзя удалить SysAdmin' });
  if (target.role === 'admin' && me.role !== 'sysadmin') return res.status(403).json({ error: 'Только SysAdmin может удалять админов' });
  if (target.avatar_url) {
    try { const p = path.join(UPLOAD_DIR, target.avatar_url.split('?')[0].replace('/uploads/', '')); if (fs.existsSync(p)) fs.unlinkSync(p); } catch (e) {}
  }
  const userMsgIds = db.messages.filter(m => m.sender_id === target.id).map(m => m.id);
  db.attachments = db.attachments.filter(a => !userMsgIds.includes(a.message_id));
  db.messages = db.messages.filter(m => m.sender_id !== target.id);
  db.chat_members = db.chat_members.filter(m => m.user_id !== target.id);
  db.blocks = db.blocks.filter(b => b.blocker !== target.id && b.blocked !== target.id);
  db.users = db.users.filter(u => u.id !== target.id);
  saveDb();
  io.to(`user:${target.id}`).emit('forceLogout', { deleted: true });
  io.emit('refreshData');
  res.json({ ok: true });
});

app.post('/api/admin/generate-invite', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me) return res.status(403).json({ error: 'Доступ запрещён' });
  const myRank = ROLE_RANK[me.role] || 0;
  if (myRank < 2) return res.status(403).json({ error: 'Недостаточно прав для создания инвайтов' });
  const { role } = req.body;
  if (!role || !ROLE_RANK[role]) return res.status(400).json({ error: 'Неверная роль' });
  if (ROLE_RANK[role] >= myRank) return res.status(403).json({ error: `Вы (${ROLE_LABEL[me.role]}) можете выдавать инвайты только для ролей ниже вашей.` });
  const code = 'INV-' + crypto.randomBytes(3).toString('hex').toUpperCase() + '-' + String(role).toUpperCase();
  db.invite_codes.push({ code, role, created_by: me.username, created_by_role: me.role, created_at: Math.floor(Date.now() / 1000), used: false });
  saveDb();
  res.json({ code, role });
});

app.post('/api/admin/set-role', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  const { username, role } = req.body;
  if (!['user', 'helper', 'moderator', 'admin', 'sysadmin'].includes(role)) return res.status(400).json({ error: 'Неизвестная роль' });
  const target = findUserByUsername(username);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.id === me.id) return res.status(400).json({ error: 'Нельзя изменить свою роль' });
  if ((role === 'admin' || role === 'sysadmin') && me.role !== 'sysadmin') return res.status(403).json({ error: 'Только SysAdmin может назначать админов' });
  if (target.role === 'sysadmin' && me.role !== 'sysadmin') return res.status(403).json({ error: 'Только SysAdmin может менять роль SysAdmin' });
  target.role = role;
  saveDb();
  io.to(`user:${target.id}`).emit('roleChanged', { newRole: role });
  io.emit('refreshData');
  res.json({ ok: true });
});

app.get('/api/admin/users-list', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin', 'moderator', 'helper'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  const canSeeIp = (me.role === 'sysadmin');
  const users = db.users.filter(u => u.role !== 'sysadmin').map(u => ({
      id: u.id, username: u.username, role: u.role || 'user', status: u.status || 'offline',
      avatarUrl: u.avatar_url || null, ip: canSeeIp ? (u.ip || 'Скрыт') : 'Скрыт',
      ban_expires: u.ban_expires || 0, created_at: u.created_at || 0
    })).sort((a, b) => {
      const diff = (ROLE_RANK[b.role] || 0) - (ROLE_RANK[a.role] || 0);
      if (diff !== 0) return diff;
      return a.username.localeCompare(b.username);
    });
  res.json(users);
});

app.get('/api/admin/logs', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  res.json({ logs: [] });
});

// ================= USERS =================
app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(publicUser(user));
});

app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = (req.query.q || '').toString().toLowerCase().trim().replace(/^@/, '');
  if (!q) return res.json([]);
  const results = db.users.filter(u => u.id !== req.userId && u.username.toLowerCase().includes(q)).slice(0, 20).map(u => ({
      id: u.id, username: u.username, displayName: u.display_name, avatarUrl: u.avatar_url,
      status: u.status, level: u.level || 1, role: u.role || 'user', ip: 'Скрыт', ban_expires: u.ban_expires || 0
  }));
  res.json(results);
});

app.get('/api/users/:userId', authMiddleware, (req, res) => {
  const target = db.users.find(u => u.id === req.params.userId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const me = db.users.find(u => u.id === req.userId);
  if (!me) return res.status(404).json({ error: 'User not found' });
  const canSeeIp = (me.role === 'sysadmin');
  res.json({
    id: target.id, username: target.username, displayName: target.display_name || null,
    avatarUrl: target.avatar_url || null, status: target.status || 'offline',
    role: target.role || 'user', ban_expires: target.ban_expires || 0,
    created_at: target.created_at || 0, ip: canSeeIp ? (target.ip || 'Скрыт') : 'Скрыт'
  });
});

app.put('/api/users/settings', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (typeof req.body.read_deleted === 'boolean') {
    if (!['sysadmin', 'admin'].includes(user.role)) return res.status(403).json({ error: 'Только Администраторы могут читать удаленные сообщения' });
    user.read_deleted = req.body.read_deleted;
  }
  saveDb();
  res.json(publicUser(user));
});

app.post('/api/users/avatar', authMiddleware, uploadSingle('avatar'), (req, res) => {
  try {
    const user = db.users.find(u => u.id === req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!req.file) return res.status(400).json({ error: 'Файл не получен' });
    if (user.avatar_url) {
      try { const oldPath = path.join(UPLOAD_DIR, user.avatar_url.split('?')[0].replace('/uploads/', '')); if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath); } catch (e) {}
    }
    user.avatar_url = '/uploads/' + req.file.filename + '?v=' + Date.now();
    saveDb();
    io.emit('refreshData');
    res.json(publicUser(user));
  } catch (e) { res.status(500).json({ error: 'Ошибка загрузки аватара' }); }
});

app.delete('/api/users/me', authMiddleware, (req, res) => {
  const idx = db.users.findIndex(u => u.id === req.userId);
  if (idx < 0) return res.status(404).json({ error: 'Not found' });
  const user = db.users[idx];
  if (user.avatar_url) {
    try { const p = path.join(UPLOAD_DIR, user.avatar_url.split('?')[0].replace('/uploads/', '')); if (fs.existsSync(p)) fs.unlinkSync(p); } catch (e) {}
  }
  const userMsgIds = db.messages.filter(m => m.sender_id === req.userId).map(m => m.id);
  db.attachments = db.attachments.filter(a => !userMsgIds.includes(a.message_id));
  db.messages = db.messages.filter(m => m.sender_id !== req.userId);
  db.chat_members = db.chat_members.filter(m => m.user_id !== req.userId);
  db.blocks = db.blocks.filter(b => b.blocker !== req.userId && b.blocked !== req.userId);
  db.users.splice(idx, 1);
  saveDb();
  io.emit('refreshData');
  res.json({ ok: true });
});

app.post('/api/users/:userId/block', authMiddleware, (req, res) => {
  const targetId = req.params.userId;
  if (targetId === req.userId) return res.status(400).json({ error: 'Нельзя заблокировать себя' });
  if (!db.users.find(u => u.id === targetId)) return res.status(404).json({ error: 'User not found' });
  if (!db.blocks.find(b => b.blocker === req.userId && b.blocked === targetId)) {
    db.blocks.push({ id: genId(), blocker: req.userId, blocked: targetId, created_at: Math.floor(Date.now() / 1000) });
    saveDb();
  }
  res.json({ ok: true });
});

app.post('/api/users/:userId/unblock', authMiddleware, (req, res) => {
  db.blocks = db.blocks.filter(b => !(b.blocker === req.userId && b.blocked === req.params.userId));
  saveDb();
  res.json({ ok: true });
});

// ================= CHATS & MESSAGES =================
app.get('/api/chats', authMiddleware, (req, res) => {
  const myChatIds = db.chat_members.filter(m => m.user_id === req.userId).map(m => m.chat_id);
  const chats = db.chats.filter(c => myChatIds.includes(c.id)).map(c => {
    const members = db.chat_members.filter(m => m.chat_id === c.id);
    const isSelf = members.length === 1 && members[0].user_id === req.userId;
    const otherId = isSelf ? req.userId : members.find(m => m.user_id !== req.userId)?.user_id;
    const other = otherId ? db.users.find(u => u.id === otherId) : null;
    let banExpires = other ? (other.ban_expires || 0) : 0;
    if (banExpires > 0 && banExpires <= Date.now()) banExpires = 0;
    return {
      id: c.id, name: isSelf ? 'Избранное' : (other ? other.username : (c.name || 'Chat')),
      avatarUrl: other ? other.avatar_url : null, otherUserId: other ? other.id : null,
      role: other ? other.role : 'user', isBlocked: isSelf ? false : chatIsBlocked(c.id, req.userId),
      ban_expires: banExpires, createdAt: c.created_at, isSelf: isSelf
    };
  });
  res.json(chats);
});

app.post('/api/chats', authMiddleware, (req, res) => {
  const userId = req.body.userId || req.userId;
  const isSelf = (userId === req.userId);
  const other = db.users.find(u => u.id === userId);
  if (!other) return res.status(404).json({ error: 'User not found' });

  const myChatIds = db.chat_members.filter(m => m.user_id === req.userId).map(m => m.chat_id);
  for (const chatId of myChatIds) {
    const members = db.chat_members.filter(m => m.chat_id === chatId);
    if (isSelf && members.length === 1 && members[0].user_id === req.userId) {
      return res.json({ id: chatId, name: 'Избранное', avatarUrl: other.avatar_url, otherUserId: other.id, role: other.role, isBlocked: false, isSelf: true, ban_expires: 0 });
    }
    if (!isSelf && members.length === 2 && members.some(m => m.user_id === userId)) {
      return res.json({ id: chatId, name: other.username, avatarUrl: other.avatar_url, otherUserId: other.id, role: other.role, isBlocked: chatIsBlocked(chatId, req.userId), isSelf: false, ban_expires: other.ban_expires || 0 });
    }
  }

  const chatId = genId();
  db.chats.push({ id: chatId, created_at: Math.floor(Date.now() / 1000) });
  db.chat_members.push({ id: genId(), chat_id: chatId, user_id: req.userId });
  if (!isSelf) db.chat_members.push({ id: genId(), chat_id: chatId, user_id: other.id });
  saveDb();
  res.json({ id: chatId, name: isSelf ? 'Избранное' : other.username, avatarUrl: other.avatar_url, otherUserId: other.id, role: other.role, isBlocked: false, isSelf: isSelf, ban_expires: isSelf ? 0 : (other.ban_expires || 0) });
});

function buildMessagePayload(m) {
  const sender = db.users.find(u => u.id === m.sender_id);
  const atts = db.attachments.filter(a => a.message_id === m.id);
  const members = db.chat_members.filter(cm => cm.chat_id === m.chat_id);
  const otherMembers = members.filter(cm => cm.user_id !== m.sender_id);
  const isSelfChat = otherMembers.length === 0;
  let delivered = false, read = false;
  if (!isSelfChat) {
    const deliveredTo = m.delivered_to || [];
    const readBy = m.read_by || [];
    delivered = otherMembers.every(om => deliveredTo.includes(om.user_id));
    read = otherMembers.every(om => readBy.includes(om.user_id));
  }
  return {
    id: m.id, chatId: m.chat_id, text: m.text,
    sender: sender ? publicUser(sender) : { id: m.sender_id, username: 'Unknown' },
    createdAt: m.created_at, is_deleted: m.is_deleted || false,
    delivered, read, isSelfChat,
    attachments: atts.map(a => ({ url: a.url, mime: a.mime_type, name: a.original_name, size: a.size }))
  };
}

app.get('/api/chats/:chatId/messages', authMiddleware, (req, res) => {
  if (!db.chat_members.find(m => m.chat_id === req.params.chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });
  const messages = db.messages.filter(m => m.chat_id === req.params.chatId).sort((a, b) => a.created_at - b.created_at).map(buildMessagePayload);
  res.json(messages);
});

app.post('/api/chats/:chatId/messages', authMiddleware, (req, res) => {
  const chatId = req.params.chatId;
  if (!db.chat_members.find(m => m.chat_id === chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });
  if (chatIsBlocked(chatId, req.userId)) return res.status(403).json({ error: 'Пользователь заблокирован' });

  const { text } = req.body;
  if (!text || typeof text !== 'string' || !text.trim()) return res.status(400).json({ error: 'Empty message' });

  const msgId = genId();
  const msg = {
    id: msgId, chat_id: chatId, sender_id: req.userId, text: text.slice(0, 4000),
    created_at: Math.floor(Date.now() / 1000), is_deleted: false, delivered_to: [], read_by: []
  };

  const otherMembers = db.chat_members.filter(cm => cm.chat_id === chatId && cm.user_id !== req.userId);
  otherMembers.forEach(om => {
    const room = io.sockets.adapter.rooms.get(`user:${om.user_id}`);
    if (room && room.size > 0) msg.delivered_to.push(om.user_id);
  });

  db.messages.push(msg);
  saveDb();

  const payload = buildMessagePayload(msg);
  emitToChatMembers(chatId, 'newMessage', payload);
  res.json(payload);
});

// #SECTION: S3_GET_UPLOAD_URL
app.post('/api/chats/:chatId/get-upload-url', authMiddleware, async (req, res) => {
  const chatId = req.params.chatId;
  if (!db.chat_members.find(m => m.chat_id === chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });
  if (chatIsBlocked(chatId, req.userId)) return res.status(403).json({ error: 'Пользователь заблокирован' });

  const { fileName, fileType } = req.body;
  if (!fileName || !fileType) return res.status(400).json({ error: 'Нет данных о файле' });

  const ext = path.extname(fileName).toLowerCase();
  if (!ALLOWED_EXT.has(ext)) return res.status(400).json({ error: 'Недопустимый тип файла: ' + ext });

  const key = `uploads/${genId()}${ext}`;
  const command = new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, ContentType: fileType });

  try {
    const uploadUrl = await getSignedUrl(s3, command, { expiresIn: 900 });
    res.json({ uploadUrl, key });
  } catch (err) {
    console.error('S3 error:', err);
    res.status(500).json({ error: 'Ошибка создания ссылки S3' });
  }
});

// #SECTION: S3_CONFIRM_UPLOAD
app.post('/api/chats/:chatId/confirm-upload', authMiddleware, (req, res) => {
  const chatId = req.params.chatId;
  if (!db.chat_members.find(m => m.chat_id === chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });

  const { files, caption } = req.body;
  if (!files || !files.length) return res.status(400).json({ error: 'Нет файлов' });

  const msgId = genId();
  const msg = {
    id: msgId, chat_id: chatId, sender_id: req.userId,
    text: (caption || '').slice(0, 4000),
    created_at: Math.floor(Date.now() / 1000), is_deleted: false, delivered_to: [], read_by: []
  };

  const otherMembers = db.chat_members.filter(cm => cm.chat_id === chatId && cm.user_id !== req.userId);
  otherMembers.forEach(om => {
    const room = io.sockets.adapter.rooms.get(`user:${om.user_id}`);
    if (room && room.size > 0) msg.delivered_to.push(om.user_id);
  });

  db.messages.push(msg);
  files.forEach(f => {
    db.attachments.push({
      id: genId(), message_id: msgId, storage_key: f.key,
      url: `/api/files/${f.key}`, mime_type: f.type, original_name: f.name, size: f.size
    });
  });
  saveDb();

  const payload = buildMessagePayload(msg);
  emitToChatMembers(chatId, 'newMessage', payload);
  res.json(payload);
});

// #SECTION: S3_DOWNLOAD_FILE
app.get('/api/files/:key', authMiddleware, async (req, res) => {
  try {
    const att = db.attachments.find(a => a.storage_key === req.params.key);
    if (!att) return res.status(404).send('Файл не найден');
    const msg = db.messages.find(m => m.id === att.message_id);
    if (!msg) return res.status(404).send('Сообщение не найдено');
    const isMember = db.chat_members.some(cm => cm.chat_id === msg.chat_id && cm.user_id === req.userId);
    if (!isMember) return res.status(403).send('Доступ запрещен');

    const command = new GetObjectCommand({ Bucket: S3_BUCKET, Key: req.params.key });
    const url = await getSignedUrl(s3, command, { expiresIn: 3600 });
    res.redirect(url);
  } catch (err) {
    console.error('S3 download error:', err);
    res.status(500).send('Ошибка скачивания');
  }
});

app.post('/api/chats/:chatId/mark-read', authMiddleware, (req, res) => {
  const chatId = req.params.chatId;
  if (!db.chat_members.find(m => m.chat_id === chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });
  const senderMsgs = {};
  db.messages.forEach(m => {
    if (m.chat_id !== chatId || m.sender_id === req.userId) return;
    if (!m.delivered_to) m.delivered_to = [];
    if (!m.read_by) m.read_by = [];
    let changed = false;
    if (!m.delivered_to.includes(req.userId)) { m.delivered_to.push(req.userId); changed = true; }
    if (!m.read_by.includes(req.userId)) { m.read_by.push(req.userId); changed = true; }
    if (changed) {
      if (!senderMsgs[m.sender_id]) senderMsgs[m.sender_id] = [];
      senderMsgs[m.sender_id].push(m.id);
    }
  });
  if (Object.keys(senderMsgs).length) {
    saveDb();
    Object.entries(senderMsgs).forEach(([senderId, ids]) => {
      io.to(`user:${senderId}`).emit('messagesRead', { chatId, readerId: req.userId, messageIds: ids });
    });
  }
  res.json({ ok: true });
});

app.delete('/api/chats/:chatId/clear', authMiddleware, (req, res) => {
  const chatId = req.params.chatId;
  if (!db.chat_members.find(m => m.chat_id === chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });
  const scope = (req.body && req.body.scope) || 'me';
  if (scope === 'all') {
    const me = db.users.find(u => u.id === req.userId);
    const isAdmin = ['sysadmin', 'admin', 'moderator'].includes(me.role);
    if (isAdmin) {
      const msgIds = db.messages.filter(m => m.chat_id === chatId).map(m => m.id);
      db.attachments = db.attachments.filter(a => !msgIds.includes(a.message_id));
      db.messages = db.messages.filter(m => m.chat_id !== chatId);
    } else {
      db.messages.filter(m => m.chat_id === chatId).forEach(m => m.is_deleted = true);
    }
    saveDb();
    emitToChatMembers(chatId, 'chatCleared', { chatId, scope: 'all' });
  }
  res.json({ ok: true });
});

app.delete('/api/messages/:messageId', authMiddleware, (req, res) => {
  const msg = db.messages.find(m => m.id === req.params.messageId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  const me = db.users.find(u => u.id === req.userId);
  const isAdmin = me && ['sysadmin', 'admin', 'moderator'].includes(me.role);
  const isOwn = msg.sender_id === req.userId;
  const scope = (req.body && req.body.scope) || 'me';
  if (scope === 'all') {
    if (!isOwn && !isAdmin) return res.status(403).json({ error: 'Недостаточно прав' });
    msg.is_deleted = true;
    saveDb();
    emitToChatMembers(msg.chat_id, 'messageDeleted', { messageId: msg.id, type: 'all', userId: req.userId });
  }
  res.json({ ok: true });
});

app.post('/api/messages/:messageId/forward', authMiddleware, (req, res) => {
  const src = db.messages.find(m => m.id === req.params.messageId);
  if (!src) return res.status(404).json({ error: 'Message not found' });
  const { chatId } = req.body;
  if (!db.chat_members.find(m => m.chat_id === chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });
  if (chatIsBlocked(chatId, req.userId)) return res.status(403).json({ error: 'Пользователь заблокирован' });

  const newMsg = {
    id: genId(), chat_id: chatId, sender_id: req.userId, text: src.text,
    created_at: Math.floor(Date.now() / 1000), is_deleted: false, delivered_to: [], read_by: []
  };
  const otherMembers = db.chat_members.filter(cm => cm.chat_id === chatId && cm.user_id !== req.userId);
  otherMembers.forEach(om => {
    const room = io.sockets.adapter.rooms.get(`user:${om.user_id}`);
    if (room && room.size > 0) newMsg.delivered_to.push(om.user_id);
  });
  db.messages.push(newMsg);
  db.attachments.filter(a => a.message_id === src.id).forEach(a => {
    db.attachments.push({ id: genId(), message_id: newMsg.id, storage_key: a.storage_key, url: a.url, mime_type: a.mime_type, original_name: a.original_name, size: a.size });
  });
  saveDb();
  const payload = buildMessagePayload(newMsg);
  emitToChatMembers(chatId, 'newMessage', payload);
  res.json(payload);
});

// ================= AUTH =================
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, invited_by } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
    const cleanUsername = String(username).trim().replace(/^@/, '');
    if (!/^[a-z0-9_]{3,32}$/i.test(cleanUsername)) return res.status(400).json({ error: 'Ник: 3–32 символа (a-z, 0-9, _)' });
    if (password.length < 10) return res.status(400).json({ error: 'Пароль: минимум 10 символов' });

    const existing = findUserByUsername(cleanUsername);
    if (existing) {
      if (existing.ban_expires && existing.ban_expires !== 0) {
        const now = Date.now();
        if (existing.ban_expires === -1 || existing.ban_expires > now) return res.status(403).json({ error: 'Этот никнейм заблокирован', ban_expires: existing.ban_expires });
      }
      return res.status(409).json({ error: 'Ник занят' });
    }

    const ip = getRealIp(req);
    if (db.banned_ips.includes(ip)) return res.status(403).json({ error: 'Ваш IP заблокирован' });

    let userRole = 'user';
    let inviter = null;
    if (invited_by) {
      const invite = db.invite_codes.find(i => i.code === invited_by && !i.used);
      if (!invite) return res.status(400).json({ error: 'Неверный или уже использованный инвайт-код' });
      if (!ROLE_RANK[invite.role]) return res.status(400).json({ error: 'Повреждённый инвайт-код' });
      userRole = invite.role;
      inviter = invite.created_by;
      invite.used = true;
    }

    const id = genId();
    const passwordHash = await bcrypt.hash(password, 12);
    const isAdmin = cleanUsername.toLowerCase() === 'admin';

    const newUser = {
      id, username: cleanUsername, password_hash: passwordHash, status: 'online',
      created_at: Math.floor(Date.now()/1000), read_deleted: false, ip,
      role: isAdmin ? 'sysadmin' : userRole, invited_by: inviter, ban_expires: 0
    };
    db.users.push(newUser);

    const plainCodes = [];
    for (let i = 0; i < 12; i++) {
      const plain = crypto.randomBytes(5).toString('hex').toUpperCase();
      plainCodes.push(plain);
      const hash = await bcrypt.hash(plain, 10);
      db.recovery_codes.push({ id: genId(), user_id: id, code_hash: hash, used_at: null });
    }
    saveDb();
    io.emit('refreshData');
    res.json({ token: signToken(id), user: publicUser(newUser), recoveryCodes: plainCodes });
  } catch (e) { res.status(500).json({ error: 'Ошибка при регистрации' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const ip = getRealIp(req);
    if (db.banned_ips.includes(ip)) return res.status(403).json({ error: 'Ваш IP заблокирован' });

    const user = findUserByUsername(username);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Неверный ник или пароль' });

    if (user.ban_expires && user.ban_expires !== 0) {
      const now = Date.now();
      if (user.ban_expires === -1 || user.ban_expires > now) return res.status(403).json({ error: 'BANNED', ban_expires: user.ban_expires });
      else user.ban_expires = 0;
    }

    user.status = 'online';
    user.ip = ip;
    saveDb();
    io.emit('refreshData');
    res.json({ token: signToken(user.id), user: publicUser(user) });
  } catch (e) { res.status(500).json({ error: 'Ошибка при входе' }); }
});

// ================= SOCKET.IO =================
io.use((socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth?.token, JWT_SECRET);
    socket.userId = payload.sub; next();
  } catch { next(new Error('invalid token')); }
});

io.on('connection', (socket) => {
  try {
    const user = db.users.find(u => u.id === socket.userId);
    if (user) {
        if (user.ban_expires && (user.ban_expires === -1 || user.ban_expires > Date.now())) {
            socket.emit('forceLogout', { ban_expires: user.ban_expires });
            return socket.disconnect();
        }
        user.status = 'online';
        saveDb();
        io.emit('refreshData');
    }
    socket.join(`user:${socket.userId}`);

    const myChatIds = db.chat_members.filter(cm => cm.user_id === socket.userId).map(cm => cm.chat_id);
    let changed = false;
    db.messages.forEach(m => {
      if (!myChatIds.includes(m.chat_id)) return;
      if (m.sender_id === socket.userId) return;
      if (!m.delivered_to) m.delivered_to = [];
      if (!m.delivered_to.includes(socket.userId)) {
        m.delivered_to.push(socket.userId);
        io.to(`user:${m.sender_id}`).emit('messageDelivered', { messageId: m.id, chatId: m.chat_id });
        changed = true;
      }
    });
    if (changed) saveDb();

    socket.on('disconnect', () => {
      const u = db.users.find(u => u.id === socket.userId);
      if (u) { u.status = 'offline'; saveDb(); io.emit('refreshData'); }
    });
  } catch (e) {}
});

// ================= ИНИЦИАЛИЗАЦИЯ И ЗАПУСК СЕРВЕРА =================
(async () => {
  // Загружаем базу из S3 при старте
  try {
    const command = new GetObjectCommand({ Bucket: S3_BUCKET, Key: 'database/scp-db.json' });
    const response = await s3.send(command);
    const body = await response.Body.transformToString();
    db = JSON.parse(body);
    serverLog('info', 'База данных успешно загружена из S3');
  } catch (err) {
    if (err.name === 'NoSuchKey' || err.$metadata?.httpStatusCode === 404) {
      serverLog('info', 'В S3 базы нет, проверяем локальную...');
      if (fs.existsSync(DB_FILE)) {
        db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        saveDb(); // Сразу закидываем локальную базу в S3
      } else {
        serverLog('info', 'Создана новая пустая база данных');
      }
    } else {
      serverLog('error', 'Ошибка загрузки БД из S3: ' + err.message);
      if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    }
  }

  // Инициализируем массивы, если их нет
  ['blocks', 'banned_ips', 'invite_codes', 'chats', 'chat_members', 'messages', 'attachments'].forEach(key => {
    if (!db[key]) db[key] = [];
  });

  // Миграция ролей
  let migrated = false;
  db.users.forEach(u => {
    if (u.username.toLowerCase() === 'admin' && u.role === 'admin') { u.role = 'sysadmin'; migrated = true; }
    if (!u.role) u.role = 'user';
  });
  if (migrated) saveDb();

  // Теперь запускаем сервер
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n⬛ SCP Foundation Messenger запущен: http://localhost:${PORT}\n`);
  });
})();
