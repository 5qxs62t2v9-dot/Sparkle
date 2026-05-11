require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public')); // если index.html лежит в public/

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key';

// ----- Мидлвара для проверки токена -----
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Требуется авторизация' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Неверный токен' });
    req.userId = user.id;
    next();
  });
}

// ----- API АВТОРИЗАЦИИ -----
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Все поля обязательны' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await new Promise((resolve, reject) => {
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed], function(err) {
        if (err) reject(err);
        else resolve(this.lastID);
      });
    });
    const user = { id: result, username, avatar: '🐱', theme: 'auto' };
    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Пользователь уже существует' });
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Все поля обязательны' });
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Ошибка БД' });
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Неверный пароль' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar, theme: user.theme } });
  });
});

// ----- API ПРОФИЛЯ (только авторизованные) -----
app.get('/api/me', authenticateToken, (req, res) => {
  db.get('SELECT id, username, avatar, theme FROM users WHERE id = ?', [req.userId], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json(user);
  });
});

app.put('/api/me', authenticateToken, async (req, res) => {
  const { username, password, avatar, theme } = req.body;
  const updates = [];
  const params = [];
  if (username !== undefined) { updates.push('username = ?'); params.push(username); }
  if (password !== undefined) {
    const hashed = await bcrypt.hash(password, 10);
    updates.push('password = ?'); params.push(hashed);
  }
  if (avatar !== undefined) { updates.push('avatar = ?'); params.push(avatar); }
  if (theme !== undefined) { updates.push('theme = ?'); params.push(theme); }
  if (updates.length === 0) return res.status(400).json({ error: 'Нет данных для обновления' });
  params.push(req.userId);
  db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
    if (err) return res.status(500).json({ error: 'Ошибка обновления' });
    db.get('SELECT id, username, avatar, theme FROM users WHERE id = ?', [req.userId], (err, user) => {
      res.json(user);
    });
  });
});

// ----- ПОИСК ПОЛЬЗОВАТЕЛЕЙ (для создания чата) -----
app.get('/api/users', authenticateToken, (req, res) => {
  const search = req.query.search || '';
  db.all('SELECT id, username, avatar FROM users WHERE username LIKE ? AND id != ? LIMIT 20', [`%${search}%`, req.userId], (err, rows) => {
    if (err) return res.status(500).json([]);
    res.json(rows);
  });
});

// ----- СПИСОК ЧАТОВ (диалоги с последним сообщением) -----
app.get('/api/chats', authenticateToken, (req, res) => {
  const userId = req.userId;
  db.all(`
    SELECT 
      u.id as userId, u.username, u.avatar,
      (SELECT content FROM messages WHERE (from_id = ${userId} AND to_id = u.id) OR (from_id = u.id AND to_id = ${userId}) ORDER BY created_at DESC LIMIT 1) as lastMessage
    FROM users u
    WHERE u.id IN (
      SELECT DISTINCT from_id FROM messages WHERE to_id = ${userId}
      UNION
      SELECT DISTINCT to_id FROM messages WHERE from_id = ${userId}
    ) AND u.id != ${userId}
    ORDER BY (SELECT MAX(created_at) FROM messages WHERE (from_id = ${userId} AND to_id = u.id) OR (from_id = u.id AND to_id = ${userId})) DESC
  `, (err, chats) => {
    if (err) return res.status(500).json([]);
    res.json(chats);
  });
});

// ----- ИСТОРИЯ СООБЩЕНИЙ С КОНКРЕТНЫМ ПОЛЬЗОВАТЕЛЕМ -----
app.get('/api/messages/:userId', authenticateToken, (req, res) => {
  const fromId = req.userId;
  const toId = parseInt(req.params.userId);
  db.all(`
    SELECT * FROM messages 
    WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
    ORDER BY created_at ASC
  `, [fromId, toId, toId, fromId], (err, rows) => {
    if (err) return res.status(500).json([]);
    res.json(rows.map(row => ({
      id: row.id,
      fromId: row.from_id,
      toId: row.to_id,
      content: row.content,
      createdAt: row.created_at
    })));
  });
});

// ----- ОТПРАВКА СООБЩЕНИЯ -----
app.post('/api/messages', authenticateToken, async (req, res) => {
  const { toUserId, content } = req.body;
  if (!toUserId || !content?.trim()) return res.status(400).json({ error: 'Неверные данные' });
  const trimmed = content.trim();
  db.run('INSERT INTO messages (from_id, to_id, content) VALUES (?, ?, ?)', [req.userId, toUserId, trimmed], function(err) {
    if (err) return res.status(500).json({ error: 'Ошибка отправки' });
    const newMsg = { id: this.lastID, fromId: req.userId, toId: toUserId, content: trimmed, createdAt: new Date().toISOString() };
    // уведомим через сокет получателя, если он онлайн
    const receiverSocket = userSockets.get(toUserId);
    if (receiverSocket) {
      receiverSocket.emit('new_message', newMsg);
    }
    // также отправим отправителю (для обновления UI)
    const senderSocket = userSockets.get(req.userId);
    if (senderSocket) senderSocket.emit('new_message', newMsg);
    res.json(newMsg);
  });
});

// ----- WEBSOCKET для реального времени -----
const userSockets = new Map(); // userId -> socket
io.use((socket, next) => {
  const token = socket.handshake.query.token;
  if (!token) return next(new Error('Authentication error'));
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Invalid token'));
    socket.userId = decoded.id;
    next();
  });
});

io.on('connection', (socket) => {
  const userId = socket.userId;
  userSockets.set(userId, socket);
  console.log(`User ${userId} connected`);

  socket.on('send_message', async (data) => {
    const { toUserId, content } = data;
    if (!toUserId || !content?.trim()) return;
    const trimmed = content.trim();
    db.run('INSERT INTO messages (from_id, to_id, content) VALUES (?, ?, ?)', [userId, toUserId, trimmed], function(err) {
      if (err) return;
      const newMsg = { id: this.lastID, fromId: userId, toId: toUserId, content: trimmed, createdAt: new Date().toISOString() };
      const receiver = userSockets.get(toUserId);
      if (receiver) receiver.emit('new_message', newMsg);
      const sender = userSockets.get(userId);
      if (sender) sender.emit('new_message', newMsg);
    });
  });

  socket.on('disconnect', () => {
    userSockets.delete(userId);
    console.log(`User ${userId} disconnected`);
  });
});

// ----- ЗАПУСК СЕРВЕРА -----
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});