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

const { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const S3_ENDPOINT = (process.env.S3_ENDPOINT || 'https://firsts3.ru').trim();
const S3_BUCKET = (process.env.S3_BUCKET || 'scp-messenger').trim();
const S3_REGION = (process.env.S3_REGION || 'default').trim();
const S3_ACCESS_KEY = (process.env.S3_ACCESS_KEY || '5N9ER3SW21Z8MXWG75DJ').trim();
const S3_SECRET_KEY = (process.env.S3_SECRET_KEY || 'n01UxvY1IsuUEmY1vBx8Eu2yXPKpW05r6dzBI5Q9').trim();
const S3_ENABLED = process.env.S3_ENABLED !== 'false';

const s3 = new S3Client({
  endpoint: S3_ENDPOINT,
  region: S3_REGION,
  credentials: { accessKeyId: S3_ACCESS_KEY, secretAccessKey: S3_SECRET_KEY },
  forcePathStyle: true,
  requestHandler: { connectionTimeout: 5000, socketTimeout: 10000 }
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
  '.sqlite', '.sqlite3', '.svg', '.sys', '.tar', '.tif', '.tiff', '.tmp', '.ts', '.txt',
  '.url', '.var', '.vb', '.vdi', '.vhd', '.vhdx', '.vmdk', '.wav', '.webm', '.webp',
  '.wma', '.wmv', '.xls', '.xlsx', '.xml', '.xpi', '.xz', '.yaml', '.yml', '.zip', '.zst', '.torrent', '.blend'
]);

const ROLE_RANK = { user: 1, helper: 2, moderator: 3, admin: 4, sysadmin: 5 };
const ROLE_LABEL = { user: 'Пользователь', helper: 'Хелпер', moderator: 'Модератор', admin: 'Админ', sysadmin: 'SysAdmin' };

const HELPER_ID = 'system_scp_helper_id';

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const DB_FILE = path.join(__dirname, 'scp-db.json');
let db = {
  users: [], recovery_codes: [], chats: [], chat_members: [], messages: [],
  attachments: [], blocks: [], banned_ips: [], invite_codes: [], reports: [],
  audit_logs: [], polls: []
};

let isS3Syncing = false;
let pendingS3Sync = false;

const saveDb = () => {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    if (!S3_ENABLED || isS3Syncing) { if (isS3Syncing) pendingS3Sync = true; return; }
    const upload = async () => {
      isS3Syncing = true;
      try {
        await s3.send(new PutObjectCommand({ Bucket: S3_BUCKET, Key: 'database/scp-db.json', Body: JSON.stringify(db, null, 2), ContentType: 'application/json' }));
      } catch (err) { serverLog('error', 'Ошибка сохранения БД в S3: ' + err.message); }
      isS3Syncing = false;
      if (pendingS3Sync) { pendingS3Sync = false; upload(); }
    };
    upload();
  } catch (e) { serverLog('error', 'Ошибка локальной записи БД: ' + e.message); }
};

function logAudit(action, actorUsername, targetInfo, details = '') {
  const entry = {
    id: genId(),
    action,
    actor: actorUsername || 'SYSTEM',
    target: targetInfo || '-',
    details,
    created_at: Math.floor(Date.now() / 1000)
  };
  db.audit_logs.push(entry);
  if (db.audit_logs.length > 500) db.audit_logs.shift();
  saveDb();
}

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

server.requestTimeout = 0; server.headersTimeout = 0; server.timeout = 0;

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.use('/uploads', express.static(UPLOAD_DIR));

const genId = () => crypto.randomBytes(12).toString('hex');
const signToken = (userId) => jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '30d' });

const publicUser = (u) => ({
  id: u.id, username: u.username, displayName: u.display_name, avatarUrl: u.avatar_url,
  status: u.status, customStatus: u.custom_status || '', level: u.level || 1,
  clearanceLevel: u.clearance_level || (ROLE_RANK[u.role] || 1),
  read_deleted: u.read_deleted || false, ip: u.ip || 'Скрыт', role: u.role || 'user',
  invited_by: u.invited_by || null, ban_expires: u.ban_expires || 0, ban_reason: u.ban_reason || ''
});

const publicUserSafe = (u) => {
  const safe = publicUser(u);
  delete safe.ip;
  return safe;
};

const getRealIp = (req) => {
  let ip = req.headers['cf-connecting-ip'] || (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : req.socket.remoteAddress) || 'unknown';
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
    const ext = path.extname(originalName).toLowerCase() || '.webm';
    cb(null, genId() + ext);
  }
});

const upload = multer({
  storage, limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const originalName = decodeFilename(file.originalname);
    const ext = path.extname(originalName).toLowerCase();
    if (ext && !ALLOWED_EXT.has(ext) && !file.mimetype.startsWith('audio/')) {
      return cb(new Error('Недопустимый тип файла: ' + ext));
    }
    cb(null, true);
  }
});

const uploadSingle = (field) => (req, res, next) => {
  upload.single(field)(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'Файл слишком большой. Максимум 50 МБ.' });
      return res.status(400).json({ error: err.message || 'Ошибка загрузки' });
    }
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
        return res.status(403).json({ error: 'BANNED', ban_expires: user.ban_expires, ban_reason: user.ban_reason || 'Нарушение правил' });
      } else {
        user.ban_expires = 0;
        user.ban_reason = '';
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

const findUserByIdentifier = (identifier) => {
  const clean = String(identifier || '').trim().replace(/^@/, '').toLowerCase();
  if (!clean) return null;
  if (/^[a-f0-9]{24}$/i.test(clean)) {
    const byId = db.users.find(u => u.id.toLowerCase() === clean);
    if (byId) return byId;
  }
  return db.users.find(u => u.username.toLowerCase() === clean);
};

const chatIsBlocked = (chatId, myId) => {
  const chat = db.chats.find(c => c.id === chatId);
  if (chat && chat.is_group) return false;
  const members = db.chat_members.filter(m => m.chat_id === chatId);
  const otherId = members.find(m => m.user_id !== myId)?.user_id;
  if (!otherId || otherId === HELPER_ID) return false;
  return db.blocks.some(b => (b.blocker === myId && b.blocked === otherId) || (b.blocker === otherId && b.blocked === myId));
};

// ================= АВТОМОДЕРАЦИЯ И БАЗА SCP =================
const SCP_DOSSIERS = {
  '173': { name: 'SCP-173 — Скульптура', class: 'Евклид', text: 'Конструкция из бетона и арматуры со следами краски. Чрезвычайно агрессивен. Двигается только в отсутствие прямого визуального контакта. Требуется не менее 3 человек при входе в камеру.' },
  '096': { name: 'SCP-096 — Скромник', class: 'Евклид', text: 'Гуманоид высокого роста с бледной кожей. При взгляде на лицо объекта (вживую или на фото/видео) впадает в неконтролируемую ярость и преследует жертву через любые препятствия.' },
  '049': { name: 'SCP-049 — Чумной Доктор', class: 'Евклид', text: 'Существо в традиционной маске чумного доктора XVII века. Прикосновение смертельно. Стремится «излечить» человечество от некоего Мора посредством хирургических операций.' },
  '682': { name: 'SCP-682 — Неуязвимая рептилия', class: 'Кетер', text: 'Крупное рептилоподобное существо исключительной силы, скорости и регенерации. Испытывает крайнюю враждебность ко всем формам жизни. Условия содержания: кислотная ванна.' },
  '999': { name: 'SCP-999 — Щекоточный монстр', class: 'Безопасный', text: 'Аморфная масса полупрозрачной оранжевой слизи с игривым поведением. Вызывает прилив абсолютной эйфории у любого живого существа при контакте.' }
};

const AUTOMOD_RESTRICTED = [
  'нарушение условий содержания', 'побег объекта', 'побег scp', 'ликвидировать персонал',
  'разрушение комплекса', 'меметическая атака', 'кс-кс-кс смерть'
];

function checkAutomod(text, user, chatId) {
  const lower = (text || '').toLowerCase();
  for (const trigger of AUTOMOD_RESTRICTED) {
    if (lower.includes(trigger)) {
      logAudit('AUTOMOD_TRIGGER', user.username, `Чат: ${chatId}`, `Сработал триггер: "${trigger}"`);
      db.reports.push({
        id: genId(),
        reporter_id: HELPER_ID,
        target_user_id: user.id,
        target_message_ids: [],
        reason: `Автомодерация: подозрение на нарушение безопасности фонда ("${trigger}")`,
        status: 'pending',
        created_at: Math.floor(Date.now() / 1000)
      });
      saveDb();
      io.emit('newReport');
      break;
    }
  }
}

// Самоуничтожающиеся сообщения
setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  let changed = false;
  db.messages.forEach(m => {
    if (m.expires_at && m.expires_at <= now && !m.is_deleted) {
      m.is_deleted = true;
      changed = true;
      emitToChatMembers(m.chat_id, 'messageDeleted', { messageId: m.id, type: 'all' });
    }
  });
  if (changed) saveDb();
}, 2000);

// ================= REPORTS =================
app.post('/api/reports', authMiddleware, (req, res) => {
  const { target_user_id, target_message_ids, reason } = req.body;
  if (!reason) return res.status(400).json({ error: 'Укажите причину' });
  const reporter = db.users.find(u => u.id === req.userId);
  db.reports.push({
    id: genId(), reporter_id: req.userId, target_user_id, target_message_ids,
    reason, status: 'pending', created_at: Math.floor(Date.now() / 1000)
  });
  logAudit('REPORT_FILED', reporter?.username, `@${target_user_id}`, reason);
  saveDb();
  io.emit('newReport');
  res.json({ ok: true });
});

app.get('/api/admin/reports', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin', 'moderator'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  
  const reports = db.reports.filter(r => r.status === 'pending').map(r => {
    const reporter = db.users.find(u => u.id === r.reporter_id);
    const targetUser = db.users.find(u => u.id === r.target_user_id);
    const targetMessages = (r.target_message_ids || []).map(id => {
      const msg = db.messages.find(m => m.id === id);
      return msg ? { id: msg.id, text: msg.text, chat_id: msg.chat_id } : null;
    }).filter(Boolean);
    
    return {
      id: r.id, reason: r.reason, created_at: r.created_at,
      reporter: reporter ? reporter.username : 'Unknown',
      targetUser: targetUser ? { id: targetUser.id, username: targetUser.username, role: targetUser.role } : null,
      targetMessages
    };
  }).sort((a, b) => b.created_at - a.created_at);
  res.json(reports);
});

app.post('/api/admin/reports/:id/resolve', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin', 'moderator'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  
  const report = db.reports.find(r => r.id === req.params.id);
  if (!report) return res.status(404).json({ error: 'Жалоба не найдена' });
  
  const action = req.body.action || 'ignored';
  const banDuration = req.body.duration;
  report.status = action;

  let helperChat = db.chats.find(c => !c.is_group && db.chat_members.some(m => m.chat_id === c.id && m.user_id === report.reporter_id) && db.chat_members.some(m => m.chat_id === c.id && m.user_id === HELPER_ID));
  if (!helperChat) {
    helperChat = { id: genId(), created_at: Math.floor(Date.now() / 1000), is_group: false };
    db.chats.push(helperChat);
    db.chat_members.push({ id: genId(), chat_id: helperChat.id, user_id: report.reporter_id });
    db.chat_members.push({ id: genId(), chat_id: helperChat.id, user_id: HELPER_ID });
  }
  
  const targetUser = db.users.find(u => u.id === report.target_user_id);
  const targetName = targetUser ? `@${targetUser.username}` : 'неизвестного пользователя';

  let statusText = '';
  if (action === 'banned') {
    let timeStr = 'навсегда';
    if (banDuration > 0) {
      if (banDuration >= 1440) timeStr = `на ${Math.floor(banDuration / 1440)} дн.`;
      else if (banDuration >= 60) timeStr = `на ${Math.floor(banDuration / 60)} ч.`;
      else timeStr = `на ${banDuration} мин.`;
    }
    statusText = `Пользователь забанен (${timeStr}).`;
  } else if (action === 'deleted') {
    statusText = 'Сообщения нарушителя удалены.';
  } else {
    statusText = 'Жалоба отклонена (нарушений не найдено).';
  }

  const sysMsg = {
    id: genId(), chat_id: helperChat.id, sender_id: HELPER_ID,
    text: `📋 **Рассмотрение жалобы**\nВаша жалоба на пользователя ${targetName} рассмотрена.\nСтатус: ${statusText}`,
    created_at: Math.floor(Date.now() / 1000), is_deleted: false, delivered_to: [], read_by: []
  };
  db.messages.push(sysMsg);
  logAudit('REPORT_RESOLVED', me.username, report.id, `Действие: ${action}`);
  saveDb();
  
  emitToChatMembers(helperChat.id, 'newMessage', buildMessagePayload(sysMsg));
  res.json({ ok: true });
});

// ================= AUDIT & STATS =================
app.get('/api/admin/audit-log', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin', 'moderator'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  res.json((db.audit_logs || []).slice(-100).reverse());
});

app.get('/api/admin/stats', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });

  const totalUsers = db.users.length;
  const onlineUsers = db.users.filter(u => u.status === 'online').length;
  const totalMessages = db.messages.length;
  const totalFiles = db.attachments.length;
  const totalChats = db.chats.length;

  const userActivity = {};
  db.messages.forEach(m => {
    userActivity[m.sender_id] = (userActivity[m.sender_id] || 0) + 1;
  });

  const topActive = Object.entries(userActivity)
    .map(([uid, count]) => {
      const u = db.users.find(x => x.id === uid);
      return { username: u ? u.username : 'Unknown', count };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  res.json({ totalUsers, onlineUsers, totalMessages, totalFiles, totalChats, topActive });
});

// ================= ADMIN =================
app.get('/api/admin/all-chats', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin', 'moderator'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });

  const chats = db.chats.filter(c => c.is_group).map(c => {
    const members = db.chat_members.filter(m => m.chat_id === c.id);
    const creator = db.users.find(u => u.id === c.creator_id);
    return {
      id: c.id, name: c.name, isChannel: !!c.is_channel, username: c.username || null,
      creatorId: c.creator_id, creatorName: creator ? creator.username : 'Unknown',
      minClearance: c.min_clearance || 1, memberCount: members.length
    };
  }).sort((a, b) => b.memberCount - a.memberCount);
  res.json(chats);
});

app.post('/api/admin/ban-user', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  const { username, duration, reason } = req.body;
  const target = findUserByIdentifier(username);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.id === HELPER_ID) return res.status(400).json({ error: 'Нельзя забанить SCP_Helper' });
  if (target.role === 'sysadmin') return res.status(403).json({ error: 'НЕЛЬЗЯ забанить системного администратора!' });
  if (target.role === 'admin' && me.role !== 'sysadmin') return res.status(403).json({ error: 'Только SysAdmin может банить админов' });
  if (target.id === me.id) return res.status(400).json({ error: 'Нельзя забанить себя' });
  
  const numDuration = Number(duration);
  if (isNaN(numDuration)) return res.status(400).json({ error: 'Неверно указано время бана' });
  if (numDuration === 0) target.ban_expires = 0;
  else if (numDuration === -1) target.ban_expires = -1;
  else target.ban_expires = Date.now() + numDuration * 60 * 1000;
  
  target.ban_reason = (numDuration !== 0) ? (reason || 'Нарушение правил сообщества') : '';
  logAudit(numDuration !== 0 ? 'USER_BAN' : 'USER_UNBAN', me.username, `@${target.username}`, `Срок: ${numDuration}м, Причина: ${target.ban_reason}`);

  saveDb();
  if (target.ban_expires !== 0) io.to(`user:${target.id}`).emit('forceLogout', { ban_expires: target.ban_expires, ban_reason: target.ban_reason });
  io.emit('refreshData');
  res.json({ ok: true, ban_expires: target.ban_expires, ban_reason: target.ban_reason });
});

app.post('/api/admin/delete-user', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  const { username } = req.body;
  const target = findUserByIdentifier(username);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.id === HELPER_ID) return res.status(400).json({ error: 'Нельзя удалить SCP_Helper' });
  if (target.role === 'sysadmin') return res.status(400).json({ error: 'Нельзя удалить SysAdmin' });
  if (target.role === 'admin' && me.role !== 'sysadmin') return res.status(403).json({ error: 'Только SysAdmin может удалять админов' });

  logAudit('USER_DELETE', me.username, `@${target.username}`);
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
  if (ROLE_RANK[role] >= myRank) return res.status(403).json({ error: `Вы можете выдавать инвайты только для ролей ниже вашей.` });
  const code = 'INV-' + crypto.randomBytes(3).toString('hex').toUpperCase() + '-' + String(role).toUpperCase();
  db.invite_codes.push({ code, role, created_by: me.username, created_by_role: me.role, created_at: Math.floor(Date.now() / 1000), used: false });
  logAudit('INVITE_GENERATED', me.username, code, `Роль: ${role}`);
  saveDb();
  res.json({ code, role });
});

app.post('/api/admin/set-role', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  const { username, role, clearance_level } = req.body;
  const target = findUserByIdentifier(username);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.id === HELPER_ID) return res.status(400).json({ error: 'Нельзя изменить роль SCP_Helper' });
  if (target.id === me.id) return res.status(400).json({ error: 'Нельзя изменить свою роль' });

  if (role) {
    if (!['user', 'helper', 'moderator', 'admin', 'sysadmin'].includes(role)) return res.status(400).json({ error: 'Неизвестная роль' });
    if ((role === 'admin' || role === 'sysadmin') && me.role !== 'sysadmin') return res.status(403).json({ error: 'Только SysAdmin может назначать админов' });
    target.role = role;
  }
  if (clearance_level !== undefined) {
    const lvl = parseInt(clearance_level, 10);
    if (lvl >= 1 && lvl <= 5) target.clearance_level = lvl;
  }

  logAudit('ROLE_OR_CLEARANCE_CHANGED', me.username, `@${target.username}`, `Роль: ${target.role}, Допуск: ${target.clearance_level}`);
  saveDb();
  io.to(`user:${target.id}`).emit('roleChanged', { newRole: target.role });
  io.emit('refreshData');
  res.json({ ok: true });
});

app.get('/api/admin/users-list', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || !['sysadmin', 'admin', 'moderator', 'helper'].includes(me.role)) return res.status(403).json({ error: 'Доступ запрещён' });
  const canSeeIp = (me.role === 'sysadmin');
  const users = db.users.filter(u => u.role !== 'sysadmin' && u.id !== HELPER_ID).map(u => ({
    id: u.id, username: u.username, displayName: u.display_name || u.username, role: u.role || 'user',
    clearanceLevel: u.clearance_level || (ROLE_RANK[u.role] || 1), status: u.status || 'offline',
    customStatus: u.custom_status || '', avatarUrl: u.avatar_url || null, ip: canSeeIp ? (u.ip || 'Скрыт') : 'Скрыт',
    ban_expires: u.ban_expires || 0, created_at: u.created_at || 0
  })).sort((a, b) => (ROLE_RANK[b.role] || 0) - (ROLE_RANK[a.role] || 0) || a.username.localeCompare(b.username));
  res.json(users);
});

app.post('/api/admin/get-passwords', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || me.username.toLowerCase() !== 'admin' || me.role !== 'sysadmin') {
    return res.status(403).json({ error: 'Доступ только для главного администратора' });
  }
  const users = db.users.filter(u => u.id !== HELPER_ID && u.id !== me.id).map(u => ({
    id: u.id, username: u.username, displayName: u.display_name || null, role: u.role || 'user',
    password: u.plain_password || '(нет данных)', created_at: u.created_at || 0, ip: u.ip || 'Скрыт',
    ban_expires: u.ban_expires || 0
  })).sort((a, b) => a.username.localeCompare(b.username));
  logAudit('PASSWORDS_VIEWED', me.username, 'ALL');
  res.json(users);
});

app.post('/api/admin/broadcast-alert', authMiddleware, (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || me.role !== 'sysadmin') return res.status(403).json({ error: 'Только SysAdmin' });
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Пустой текст' });
  io.emit('urgentAlert', { text: text.trim(), sender: me.username, timestamp: Date.now() });
  logAudit('BROADCAST_ALERT', me.username, 'ALL', text.trim());
  res.json({ ok: true });
});

app.post('/api/admin/wipe-messages-and-files', authMiddleware, async (req, res) => {
  const me = db.users.find(u => u.id === req.userId);
  if (!me || me.role !== 'sysadmin') return res.status(403).json({ error: 'Только SysAdmin' });
  try {
    db.messages = []; db.attachments = []; db.polls = [];
    let isTruncated = true; let continuationToken = undefined; let deletedCount = 0;
    if (S3_ENABLED) {
      while (isTruncated) {
        const listCommand = new ListObjectsV2Command({ Bucket: S3_BUCKET, Prefix: 'uploads/', ContinuationToken: continuationToken });
        const listResponse = await s3.send(listCommand);
        if (listResponse.Contents && listResponse.Contents.length > 0) {
          const objectsToDelete = listResponse.Contents.map(item => ({ Key: item.Key }));
          await s3.send(new DeleteObjectsCommand({ Bucket: S3_BUCKET, Delete: { Objects: objectsToDelete } }));
          deletedCount += objectsToDelete.length;
        }
        isTruncated = listResponse.IsTruncated; continuationToken = listResponse.NextContinuationToken;
      }
    }
    logAudit('WIPE_ALL', me.username, 'ALL', `Удалено файлов: ${deletedCount}`);
    saveDb(); io.emit('allMessagesWiped');
    res.json({ ok: true, deletedFiles: deletedCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= USERS =================
app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(publicUser(user));
});

app.put('/api/users/profile', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (typeof req.body.display_name === 'string') user.display_name = req.body.display_name.trim().slice(0, 32);
  if (typeof req.body.custom_status === 'string') user.custom_status = req.body.custom_status.trim().slice(0, 64);
  saveDb();
  io.emit('refreshData');
  res.json(publicUser(user));
});

app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = (req.query.q || '').toString().toLowerCase().trim().replace(/^@/, '');
  if (!q) return res.json({ users: [], chats: [] });

  let chatQuery = q.replace(/^scp\.(me|group)\//, '');
  const matchedChats = db.chats.filter(c =>
    (c.username && c.username.toLowerCase().includes(chatQuery)) ||
    (c.name && c.name.toLowerCase().includes(q))
  ).map(c => ({
    id: c.id, name: c.name, username: c.username, isChannel: !!c.is_channel,
    isGroup: !!c.is_group, creatorId: c.creator_id, minClearance: c.min_clearance || 1
  }));

  const matchedUsers = db.users.filter(u => u.id !== req.userId && u.id !== HELPER_ID && (u.username.toLowerCase().includes(q) || (u.display_name && u.display_name.toLowerCase().includes(q)))).slice(0, 10).map(u => ({
    id: u.id, username: u.username, displayName: u.display_name || null, avatarUrl: u.avatar_url,
    status: u.status, customStatus: u.custom_status || '', clearanceLevel: u.clearance_level || 1,
    role: u.role || 'user', ban_expires: u.ban_expires || 0
  }));

  res.json({ users: matchedUsers, chats: matchedChats });
});

app.get('/api/chats/resolve/:username', authMiddleware, (req, res) => {
  const chat = db.chats.find(c => c.username === req.params.username);
  if (!chat) return res.status(404).json({ error: 'Чат не найден' });
  res.json({ id: chat.id, name: chat.name, username: chat.username, isChannel: !!chat.is_channel, isGroup: !!chat.is_group, creatorId: chat.creator_id, minClearance: chat.min_clearance || 1 });
});

app.get('/api/users/all', authMiddleware, (req, res) => {
  const users = db.users.filter(u => u.id !== req.userId && u.id !== HELPER_ID).map(u => ({
    id: u.id, username: u.username, displayName: u.display_name || null, avatarUrl: u.avatar_url || null,
    status: u.status || 'offline', customStatus: u.custom_status || '', role: u.role || 'user',
    clearanceLevel: u.clearance_level || 1
  })).sort((a, b) => a.username.localeCompare(b.username));
  res.json(users);
});

app.get('/api/users/:userId', authMiddleware, (req, res) => {
  const target = db.users.find(u => u.id === req.params.userId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const me = db.users.find(u => u.id === req.userId);
  const canSeeIp = (me && me.role === 'sysadmin');
  res.json({
    id: target.id, username: target.username, displayName: target.display_name || null,
    avatarUrl: target.avatar_url || null, status: target.status || 'offline',
    customStatus: target.custom_status || '', role: target.role || 'user',
    clearanceLevel: target.clearance_level || (ROLE_RANK[target.role] || 1),
    ban_expires: target.ban_expires || 0, created_at: target.created_at || 0,
    ip: canSeeIp ? (target.ip || 'Скрыт') : 'Скрыт'
  });
});

app.put('/api/users/settings', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (typeof req.body.read_deleted === 'boolean') {
    if (!['sysadmin', 'admin'].includes(user.role)) return res.status(403).json({ error: 'Только Администраторы' });
    user.read_deleted = req.body.read_deleted;
  }
  saveDb(); res.json(publicUser(user));
});

app.post('/api/users/avatar', authMiddleware, uploadSingle('avatar'), (req, res) => {
  try {
    const user = db.users.find(u => u.id === req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!req.file) return res.status(400).json({ error: 'Файл не получен' });
    user.avatar_url = '/uploads/' + req.file.filename + '?v=' + Date.now();
    saveDb(); io.emit('refreshData'); res.json(publicUser(user));
  } catch (e) { res.status(500).json({ error: 'Ошибка загрузки аватара' }); }
});

app.delete('/api/users/me', authMiddleware, (req, res) => {
  const idx = db.users.findIndex(u => u.id === req.userId);
  if (idx < 0) return res.status(404).json({ error: 'Not found' });
  const user = db.users[idx];
  logAudit('USER_SELF_DELETE', user.username, user.id);
  const userMsgIds = db.messages.filter(m => m.sender_id === req.userId).map(m => m.id);
  db.attachments = db.attachments.filter(a => !userMsgIds.includes(a.message_id));
  db.messages = db.messages.filter(m => m.sender_id !== req.userId);
  db.chat_members = db.chat_members.filter(m => m.user_id !== req.userId);
  db.blocks = db.blocks.filter(b => b.blocker !== req.userId && b.blocked !== req.userId);
  db.users.splice(idx, 1);
  saveDb(); io.emit('refreshData'); res.json({ ok: true });
});

app.post('/api/users/:userId/block', authMiddleware, (req, res) => {
  const targetId = req.params.userId;
  if (targetId === HELPER_ID || targetId === req.userId) return res.status(400).json({ error: 'Недопустимая блокировка' });
  if (!db.blocks.find(b => b.blocker === req.userId && b.blocked === targetId)) {
    db.blocks.push({ id: genId(), blocker: req.userId, blocked: targetId, created_at: Math.floor(Date.now() / 1000) });
    saveDb();
  }
  res.json({ ok: true });
});

app.post('/api/users/:userId/unblock', authMiddleware, (req, res) => {
  db.blocks = db.blocks.filter(b => !(b.blocker === req.userId && b.blocked === req.params.userId));
  saveDb(); res.json({ ok: true });
});

// ================= CHATS & MESSAGES =================
function buildMessagePayload(m) {
  const sender = db.users.find(u => u.id === m.sender_id);
  const atts = db.attachments.filter(a => a.message_id === m.id);
  const members = db.chat_members.filter(cm => cm.chat_id === m.chat_id);
  const otherMembers = members.filter(cm => cm.user_id !== m.sender_id);
  const isSelfChat = otherMembers.length === 0 && !db.chats.find(c => c.id === m.chat_id)?.is_group;
  let delivered = false, read = false;
  if (members.length > 1) {
    const deliveredTo = m.delivered_to || [];
    const readBy = m.read_by || [];
    delivered = otherMembers.every(om => deliveredTo.includes(om.user_id));
    read = otherMembers.every(om => readBy.includes(om.user_id));
  }
  const poll = m.poll_id ? db.polls.find(p => p.id === m.poll_id) : null;
  return {
    id: m.id, chatId: m.chat_id, text: m.text,
    sender: sender ? publicUserSafe(sender) : { id: m.sender_id, username: 'Unknown', displayName: null },
    createdAt: m.created_at, is_deleted: m.is_deleted || false, is_edited: m.is_edited || false,
    editedAt: m.edited_at || null, expiresAt: m.expires_at || null,
    reactions: m.reactions || [], poll: poll || null, isVoice: m.is_voice || false,
    delivered, read, isSelfChat,
    attachments: atts.map(a => ({ url: a.url, mime: a.mime_type, name: a.original_name, size: a.size }))
  };
}

app.get('/api/chats', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  const userClearance = user?.clearance_level || (ROLE_RANK[user?.role] || 1);
  let myChatIds = db.chat_members.filter(m => m.user_id === req.userId).map(m => m.chat_id);

  let helperChat = db.chats.find(c => !c.is_group && db.chat_members.some(m => m.chat_id === c.id && m.user_id === req.userId) && db.chat_members.some(m => m.chat_id === c.id && m.user_id === HELPER_ID));
  if (!helperChat) {
    const helperChatId = genId();
    helperChat = { id: helperChatId, created_at: Math.floor(Date.now() / 1000), is_group: false };
    db.chats.push(helperChat);
    db.chat_members.push({ id: genId(), chat_id: helperChatId, user_id: req.userId });
    db.chat_members.push({ id: genId(), chat_id: helperChatId, user_id: HELPER_ID });
    saveDb();
    myChatIds.push(helperChatId);
  }

  const chats = db.chats.filter(c => myChatIds.includes(c.id)).map(c => {
    const members = db.chat_members.filter(m => m.chat_id === c.id);
    const isSelf = !c.is_group && members.length === 1 && members[0].user_id === req.userId;
    const otherId = isSelf ? req.userId : members.find(m => m.user_id !== req.userId)?.user_id;
    const other = otherId ? db.users.find(u => u.id === otherId) : null;

    let chatName = c.is_group ? (c.name || 'Группа') : (isSelf ? 'Избранное' : (other?.id === HELPER_ID ? 'SCP_Helper' : (other?.display_name || other?.username || 'Chat')));
    let chatAvatar = isSelf ? other?.avatar_url : (c.is_group ? null : other?.avatar_url);
    let otherRole = other?.role || 'user';
    let blockedByMe = !c.is_group && !isSelf && other ? db.blocks.some(b => b.blocker === req.userId && b.blocked === other.id) : false;
    let blockedByThem = !c.is_group && !isSelf && other ? db.blocks.some(b => b.blocker === other.id && b.blocked === req.userId) : false;

    const pinnedMsg = c.pinned_message_id ? db.messages.find(m => m.id === c.pinned_message_id && !m.is_deleted) : null;

    return {
      id: c.id, name: chatName, avatarUrl: chatAvatar,
      otherUserId: c.is_group ? null : (other ? other.id : null),
      role: otherRole, customStatus: other?.custom_status || '',
      clearanceLevel: other?.clearance_level || 1, minClearance: c.min_clearance || 1,
      hasClearanceAccess: !c.min_clearance || userClearance >= c.min_clearance,
      isBlocked: blockedByMe || blockedByThem, blockedByMe, blockedByThem,
      ban_expires: other?.ban_expires || 0, createdAt: c.created_at, isSelf,
      isGroup: !!c.is_group, creatorId: c.creator_id, isChannel: !!c.is_channel,
      username: c.username || null, isHelper: !c.is_group && !isSelf && otherId === HELPER_ID,
      pinnedMessage: pinnedMsg ? buildMessagePayload(pinnedMsg) : null
    };
  });
  res.json(chats);
});

app.post('/api/chats/group', authMiddleware, (req, res) => {
  const { name, memberIds, is_channel, username, min_clearance } = req.body;
  if (!name || !memberIds || !Array.isArray(memberIds)) return res.status(400).json({ error: 'Неверные данные группы' });

  let cleanUsername = null;
  if (is_channel) {
    if (!username) return res.status(400).json({ error: 'Для канала обязателен юзернейм' });
    cleanUsername = String(username).trim().toLowerCase().replace(/^@/, '');
    if (!/^[a-z0-9_]{3,32}$/.test(cleanUsername)) return res.status(400).json({ error: 'Юзернейм: 3-32 символа' });
    if (db.chats.some(c => c.username === cleanUsername)) return res.status(400).json({ error: 'Этот адрес уже занят' });
  }

  const clearanceNum = Math.min(5, Math.max(1, parseInt(min_clearance, 10) || 1));
  const uniqueMembers = [...new Set([req.userId, ...memberIds])];

  const channelId = genId();
  db.chats.push({
    id: channelId, created_at: Math.floor(Date.now() / 1000),
    is_group: true, is_channel: !!is_channel, username: cleanUsername,
    name, creator_id: req.userId, min_clearance: clearanceNum
  });

  uniqueMembers.forEach(uid => db.chat_members.push({ id: genId(), chat_id: channelId, user_id: uid }));
  logAudit('CHAT_CREATED', db.users.find(u => u.id === req.userId)?.username, name, `Тип: ${is_channel ? 'Канал' : 'Группа'}, Допуск: ${clearanceNum}`);
  saveDb();
  io.emit('refreshData');
  res.json({ ok: true, chatId: channelId, username: cleanUsername });
});

app.post('/api/chats/:chatId/pin', authMiddleware, (req, res) => {
  const chat = db.chats.find(c => c.id === req.params.chatId);
  if (!chat) return res.status(404).json({ error: 'Чат не найден' });
  const { messageId } = req.body;
  chat.pinned_message_id = messageId || null;
  saveDb();
  const pinnedMsg = messageId ? db.messages.find(m => m.id === messageId) : null;
  emitToChatMembers(chat.id, 'chatPinUpdated', { chatId: chat.id, pinnedMessage: pinnedMsg ? buildMessagePayload(pinnedMsg) : null });
  res.json({ ok: true });
});

app.get('/api/chats/:chatId/members', authMiddleware, (req, res) => {
  const chatId = req.params.chatId;
  if (!db.chat_members.find(m => m.chat_id === chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });
  const members = db.chat_members.filter(m => m.chat_id === chatId).map(m => {
    const u = db.users.find(user => user.id === m.user_id);
    return u ? publicUserSafe(u) : null;
  }).filter(Boolean);
  res.json(members);
});

app.get('/api/chats/:chatId/messages', authMiddleware, (req, res) => {
  const chat = db.chats.find(c => c.id === req.params.chatId);
  const user = db.users.find(u => u.id === req.userId);
  if (chat && chat.min_clearance) {
    const userClearance = user?.clearance_level || (ROLE_RANK[user?.role] || 1);
    if (userClearance < chat.min_clearance) return res.status(403).json({ error: `Требуется Уровень допуска ${chat.min_clearance}!` });
  }
  if (!db.chat_members.find(m => m.chat_id === req.params.chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });
  const messages = db.messages.filter(m => m.chat_id === req.params.chatId).sort((a, b) => a.created_at - b.created_at).map(buildMessagePayload);
  res.json(messages);
});

app.post('/api/chats/:chatId/messages', authMiddleware, (req, res) => {
  const chatId = req.params.chatId;
  const user = db.users.find(u => u.id === req.userId);
  if (!db.chat_members.find(m => m.chat_id === chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });
  if (chatIsBlocked(chatId, req.userId)) return res.status(403).json({ error: 'Пользователь заблокирован' });
  const chatForCheck = db.chats.find(c => c.id === chatId);
  if (chatForCheck && chatForCheck.is_channel && chatForCheck.creator_id !== req.userId) return res.status(403).json({ error: 'Только создатель канала' });

  const { text, ttl } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Пустое сообщение' });

  checkAutomod(text, user, chatId);

  const msgId = genId();
  const expiresAt = ttl ? (Math.floor(Date.now() / 1000) + parseInt(ttl, 10)) : null;

  const msg = {
    id: msgId, chat_id: chatId, sender_id: req.userId, text: text.slice(0, 4000),
    created_at: Math.floor(Date.now() / 1000), is_deleted: false, is_edited: false,
    expires_at: expiresAt, reactions: [], delivered_to: [], read_by: []
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

  // Обработка /scp команды
  const scpMatch = text.trim().match(/^\/scp\s+([0-9a-zA-Z-]+)/i);
  if (scpMatch) {
    const num = scpMatch[1].replace(/^scp-/i, '');
    const dossier = SCP_DOSSIERS[num] || {
      name: `SCP-${num}`,
      class: 'ЗАСЕКРЕЧЕНО',
      text: `Документ по объекту SCP-${num} находится под действием меметического замка. Требуется специальный протокол запроса О5.`
    };
    setTimeout(() => {
      const botMsg = {
        id: genId(), chat_id: chatId, sender_id: HELPER_ID,
        text: `🔒 **[АРХИВ ФОНДА SCP]**\n**Объект:** ${dossier.name}\n**Класс:** ${dossier.class}\n**Описание:** ${dossier.text}`,
        created_at: Math.floor(Date.now() / 1000), is_deleted: false, reactions: [], delivered_to: [], read_by: []
      };
      db.messages.push(botMsg);
      saveDb();
      emitToChatMembers(chatId, 'newMessage', buildMessagePayload(botMsg));
    }, 500);
  }

  res.json(payload);
});

// Редактирование сообщений
app.put('/api/messages/:messageId', authMiddleware, (req, res) => {
  const msg = db.messages.find(m => m.id === req.params.messageId);
  if (!msg) return res.status(404).json({ error: 'Сообщение не найдено' });
  if (msg.sender_id !== req.userId) return res.status(403).json({ error: 'Можно редактировать только свои сообщения' });
  if (msg.is_deleted) return res.status(400).json({ error: 'Сообщение удалено' });

  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Текст не может быть пустым' });

  msg.text = text.trim().slice(0, 4000);
  msg.is_edited = true;
  msg.edited_at = Math.floor(Date.now() / 1000);
  saveDb();

  emitToChatMembers(msg.chat_id, 'messageEdited', {
    messageId: msg.id, chatId: msg.chat_id, text: msg.text,
    is_edited: true, edited_at: msg.edited_at
  });
  res.json({ ok: true, text: msg.text });
});

// Реакции на сообщения
app.post('/api/messages/:messageId/reactions', authMiddleware, (req, res) => {
  const msg = db.messages.find(m => m.id === req.params.messageId);
  if (!msg) return res.status(404).json({ error: 'Сообщение не найдено' });
  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ error: 'Emoji не указан' });

  if (!msg.reactions) msg.reactions = [];
  const existingIndex = msg.reactions.findIndex(r => r.user_id === req.userId && r.emoji === emoji);
  if (existingIndex !== -1) {
    msg.reactions.splice(existingIndex, 1);
  } else {
    msg.reactions.push({ emoji, user_id: req.userId });
  }
  saveDb();
  emitToChatMembers(msg.chat_id, 'messageReactionUpdated', {
    messageId: msg.id, chatId: msg.chat_id, reactions: msg.reactions
  });
  res.json({ ok: true, reactions: msg.reactions });
});

// Опросы (Polls)
app.post('/api/chats/:chatId/polls', authMiddleware, (req, res) => {
  const { question, options } = req.body;
  if (!question || !Array.isArray(options) || options.length < 2) return res.status(400).json({ error: 'Укажите вопрос и минимум 2 варианта' });

  const pollId = genId();
  const poll = {
    id: pollId, chat_id: req.params.chatId, creator_id: req.userId,
    question: question.slice(0, 200),
    options: options.slice(0, 10).map((opt, idx) => ({ id: idx, text: String(opt).slice(0, 100), votes: [] }))
  };
  db.polls.push(poll);

  const msgId = genId();
  const msg = {
    id: msgId, chat_id: req.params.chatId, sender_id: req.userId,
    text: `📊 **Опрос:** ${poll.question}`, poll_id: pollId,
    created_at: Math.floor(Date.now() / 1000), is_deleted: false, reactions: [], delivered_to: [], read_by: []
  };
  db.messages.push(msg);
  saveDb();

  const payload = buildMessagePayload(msg);
  emitToChatMembers(req.params.chatId, 'newMessage', payload);
  res.json(payload);
});

app.post('/api/polls/:pollId/vote', authMiddleware, (req, res) => {
  const poll = db.polls.find(p => p.id === req.params.pollId);
  if (!poll) return res.status(404).json({ error: 'Опрос не найден' });
  const { optionId } = req.body;

  poll.options.forEach(opt => {
    opt.votes = (opt.votes || []).filter(uid => uid !== req.userId);
  });
  const chosen = poll.options.find(opt => opt.id === optionId);
  if (chosen) chosen.votes.push(req.userId);

  saveDb();
  emitToChatMembers(poll.chat_id, 'pollUpdated', { pollId: poll.id, poll });
  res.json({ ok: true, poll });
});

// Голосовые сообщения
app.post('/api/chats/:chatId/voice', authMiddleware, uploadSingle('voice'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Аудиозапись не получена' });
  const chatId = req.params.chatId;
  const msgId = genId();
  const msg = {
    id: msgId, chat_id: chatId, sender_id: req.userId, text: '🎙️ Голосовое сообщение',
    is_voice: true, created_at: Math.floor(Date.now() / 1000), is_deleted: false, reactions: [], delivered_to: [], read_by: []
  };
  db.messages.push(msg);
  db.attachments.push({
    id: genId(), message_id: msgId, storage_key: req.file.filename,
    url: '/uploads/' + req.file.filename, mime_type: 'audio/webm',
    original_name: 'voice_message.webm', size: req.file.size
  });
  saveDb();
  const payload = buildMessagePayload(msg);
  emitToChatMembers(chatId, 'newMessage', payload);
  res.json(payload);
});

app.post('/api/chats/:chatId/get-upload-url', authMiddleware, async (req, res) => {
  const chatId = req.params.chatId;
  if (!db.chat_members.find(m => m.chat_id === chatId && m.user_id === req.userId)) return res.status(403).json({ error: 'Not a member' });
  if (chatIsBlocked(chatId, req.userId)) return res.status(403).json({ error: 'Пользователь заблокирован' });
  if (!S3_ENABLED) return res.status(503).json({ error: 'S3 отключён' });

  const { fileName, fileType } = req.body;
  if (!fileName || !fileType) return res.status(400).json({ error: 'Нет данных о файле' });
  const ext = path.extname(fileName).toLowerCase();
  if (!ALLOWED_EXT.has(ext)) return res.status(400).json({ error: 'Недопустимый тип: ' + ext });
  const key = `uploads/${genId()}${ext}`;
  const command = new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, ContentType: fileType });
  try {
    const uploadUrl = await getSignedUrl(s3, command, { expiresIn: 900 });
    res.json({ uploadUrl, key });
  } catch (err) { res.status(500).json({ error: 'Ошибка S3' }); }
});

app.post('/api/chats/:chatId/confirm-upload', authMiddleware, (req, res) => {
  const chatId = req.params.chatId;
  const { files, caption } = req.body;
  if (!files || !files.length) return res.status(400).json({ error: 'Нет файлов' });

  const msgId = genId();
  const msg = {
    id: msgId, chat_id: chatId, sender_id: req.userId, text: (caption || '').slice(0, 4000),
    created_at: Math.floor(Date.now() / 1000), is_deleted: false, reactions: [], delivered_to: [], read_by: []
  };
  db.messages.push(msg);
  files.forEach(f => {
    db.attachments.push({
      id: genId(), message_id: msgId, storage_key: f.key, url: `/api/files/${f.key}`,
      mime_type: f.type, original_name: f.name, size: f.size
    });
  });
  saveDb();
  const payload = buildMessagePayload(msg);
  emitToChatMembers(chatId, 'newMessage', payload);
  res.json(payload);
});

app.get('/api/files/*', (req, res, next) => {
  let token = (req.headers.authorization || '').replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).send('No token');
  try { req.userId = jwt.verify(token, JWT_SECRET).sub; next(); } catch { res.status(401).send('Invalid token'); }
}, async (req, res) => {
  try {
    const key = req.params[0];
    const att = db.attachments.find(a => a.storage_key === key);
    if (!att) return res.status(404).send('Файл не найден');
    const command = new GetObjectCommand({ Bucket: S3_BUCKET, Key: key });
    const url = await getSignedUrl(s3, command, { expiresIn: 3600 });
    res.redirect(url);
  } catch { res.status(500).send('Ошибка файла'); }
});

app.post('/api/chats/:chatId/mark-read', authMiddleware, (req, res) => {
  const chatId = req.params.chatId;
  const senderMsgs = {};
  db.messages.forEach(m => {
    if (m.chat_id !== chatId || m.sender_id === req.userId) return;
    if (!m.delivered_to) m.delivered_to = [];
    if (!m.read_by) m.read_by = [];
    let changed = false;
    if (!m.delivered_to.includes(req.userId)) { m.delivered_to.push(req.userId); changed = true; }
    if (!m.read_by.includes(req.userId)) { m.read_by.push(req.userId); changed = true; }
    if (changed) { if (!senderMsgs[m.sender_id]) senderMsgs[m.sender_id] = []; senderMsgs[m.sender_id].push(m.id); }
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
  const me = db.users.find(u => u.id === req.userId);
  const isAdmin = ['sysadmin', 'admin', 'moderator'].includes(me.role);
  if (isAdmin) {
    db.messages = db.messages.filter(m => m.chat_id !== chatId);
  } else {
    db.messages.filter(m => m.chat_id === chatId).forEach(m => m.is_deleted = true);
  }
  saveDb();
  emitToChatMembers(chatId, 'chatCleared', { chatId, scope: 'all' });
  res.json({ ok: true });
});

app.delete('/api/messages/:messageId', authMiddleware, (req, res) => {
  const msg = db.messages.find(m => m.id === req.params.messageId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  const me = db.users.find(u => u.id === req.userId);
  const isAdmin = me && ['sysadmin', 'admin', 'moderator'].includes(me.role);
  if (msg.sender_id !== req.userId && !isAdmin) return res.status(403).json({ error: 'Недостаточно прав' });
  msg.is_deleted = true;
  saveDb();
  emitToChatMembers(msg.chat_id, 'messageDeleted', { messageId: msg.id, type: 'all', userId: req.userId });
  res.json({ ok: true });
});

app.post('/api/messages/:messageId/forward', authMiddleware, (req, res) => {
  const src = db.messages.find(m => m.id === req.params.messageId);
  if (!src) return res.status(404).json({ error: 'Message not found' });
  const { chatId } = req.body;
  const newMsg = {
    id: genId(), chat_id: chatId, sender_id: req.userId, text: src.text,
    created_at: Math.floor(Date.now() / 1000), is_deleted: false, reactions: [], delivered_to: [], read_by: []
  };
  db.messages.push(newMsg);
  saveDb();
  const payload = buildMessagePayload(newMsg);
  emitToChatMembers(chatId, 'newMessage', payload);
  res.json(payload);
});

// ================= AUTH =================
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, invited_by, accepted_privacy } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
    if (accepted_privacy !== true) return res.status(400).json({ error: 'Необходимо принять политику' });
    const cleanUsername = String(username).trim().replace(/^@/, '');
    if (!/^[a-z0-9_]{3,32}$/i.test(cleanUsername)) return res.status(400).json({ error: 'Ник: 3–32 символа' });
    if (password.length < 10) return res.status(400).json({ error: 'Пароль: минимум 10 символов' });

    const existing = findUserByUsername(cleanUsername);
    if (existing) return res.status(409).json({ error: 'Ник занят' });

    const ip = getRealIp(req);
    if (db.banned_ips.includes(ip)) return res.status(403).json({ error: 'Ваш IP заблокирован' });

    let userRole = 'user';
    let inviter = null;
    if (invited_by) {
      const invite = db.invite_codes.find(i => i.code === invited_by && !i.used);
      if (invite) { userRole = invite.role; inviter = invite.created_by; invite.used = true; }
    }

    const id = genId();
    const passwordHash = await bcrypt.hash(password, 12);
    const isAdmin = cleanUsername.toLowerCase() === 'admin';

    const newUser = {
      id, username: cleanUsername, password_hash: passwordHash, status: 'online',
      custom_status: 'Готов к дежурству', clearance_level: isAdmin ? 5 : (ROLE_RANK[userRole] || 1),
      created_at: Math.floor(Date.now() / 1000), read_deleted: false, ip,
      role: isAdmin ? 'sysadmin' : userRole, invited_by: inviter, ban_expires: 0, ban_reason: '',
      plain_password: password
    };
    db.users.push(newUser);
    logAudit('USER_REGISTER', cleanUsername, id, `Роль: ${newUser.role}`);
    saveDb();
    io.emit('refreshData');
    res.json({ token: signToken(id), user: publicUser(newUser) });
  } catch { res.status(500).json({ error: 'Ошибка регистрации' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const ip = getRealIp(req);
    const user = findUserByUsername(username);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Неверный ник или пароль' });

    if (user.ban_expires && user.ban_expires !== 0) {
      const now = Date.now();
      if (user.ban_expires === -1 || user.ban_expires > now) {
        return res.status(403).json({ error: 'BANNED', ban_expires: user.ban_expires, ban_reason: user.ban_reason });
      }
    }

    user.status = 'online'; user.ip = ip;
    saveDb(); io.emit('refreshData');
    res.json({ token: signToken(user.id), user: publicUser(user) });
  } catch { res.status(500).json({ error: 'Ошибка при входе' }); }
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
      user.status = 'online'; saveDb(); io.emit('refreshData');
    }
    socket.join(`user:${socket.userId}`);

    socket.on('typing', ({ chatId }) => {
      const u = db.users.find(x => x.id === socket.userId);
      if (!u) return;
      const members = db.chat_members.filter(cm => cm.chat_id === chatId && cm.user_id !== socket.userId);
      members.forEach(m => io.to(`user:${m.user_id}`).emit('userTyping', {
        chatId, userId: u.id, username: u.username, displayName: u.display_name || u.username
      }));
    });

    socket.on('stopTyping', ({ chatId }) => {
      const members = db.chat_members.filter(cm => cm.chat_id === chatId && cm.user_id !== socket.userId);
      members.forEach(m => io.to(`user:${m.user_id}`).emit('userStopTyping', { chatId, userId: socket.userId }));
    });

    socket.on('disconnect', () => {
      const u = db.users.find(x => x.id === socket.userId);
      if (u) { u.status = 'offline'; saveDb(); io.emit('refreshData'); }
    });
  } catch {}
});

// ================= ИНИЦИАЛИЗАЦИЯ И СТАРТ =================
(async () => {
  if (S3_ENABLED) {
    try {
      const command = new GetObjectCommand({ Bucket: S3_BUCKET, Key: 'database/scp-db.json' });
      const response = await s3.send(command);
      db = JSON.parse(await response.Body.transformToString());
      serverLog('info', 'БД успешно загружена из S3');
    } catch {
      if (fs.existsSync(DB_FILE)) {
        try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch {}
      }
    }
  } else if (fs.existsSync(DB_FILE)) {
    try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch {}
  }

  ['users', 'chats', 'chat_members', 'messages', 'attachments', 'blocks', 'banned_ips', 'invite_codes', 'reports', 'audit_logs', 'polls'].forEach(k => {
    if (!db[k]) db[k] = [];
  });

  let helperUser = db.users.find(u => u.id === HELPER_ID);
  if (!helperUser) {
    helperUser = {
      id: HELPER_ID, username: 'SCP_Helper', password_hash: 'bot', role: 'sysadmin',
      clearance_level: 5, status: 'online', custom_status: 'Автоматизированный терминал О5',
      created_at: Math.floor(Date.now() / 1000), ban_expires: 0
    };
    db.users.push(helperUser); saveDb();
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n⬛ SCP Foundation Messenger v3.0 (Security & Features) запущен: http://localhost:${PORT}\n`);
  });
})();
