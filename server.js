/* =========================================================
   UON Portal — Sync Server (Turso cloud database)
   ========================================================= */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');

const PORT = process.env.PORT || 8080;
const TURSO_URL = process.env.TURSO_URL || 'libsql://uon-portals-hayyat.aws-ap-south-1.turso.io';
const TURSO_TOKEN = process.env.TURSO_TOKEN || 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3ODkzMTk1NjksImlkIjoiMDFhMDliYzEtMzAwMS03YmViLTkxMWUtYmIyNmQxYjQ3ZDE0Iiwia2lkIjoieXdJa1VRSlVBQzFxcnJYYkxpbzlMd1g5ZWhkRFh0MkpsQzZSc2hITndNRSIsInJpZCI6IjA3NzVlMTBjLTg0NTUtNGJhYy1hOGVhLTJjOTA1MjA2MzM2MyJ9.pseAjHiqXGML6qWlm6EePOHtqy37DhlkjgCxRRt1UtmrfuROSQ_z82XjQkXD_EGqSTjIuR2088wVx7ApzTSYCQ';

const turso = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

/* ---------- Init tables ---------- */
async function initTables(){
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS kv (
      k TEXT PRIMARY KEY,
      v TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    )
  `);
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      role TEXT NOT NULL,
      user_id TEXT,
      created_at INTEGER NOT NULL
    )
  `);
}

/* ---------- KV helpers ---------- */
async function kvGet(k, fallback){
  const res = await turso.execute({ sql: 'SELECT v FROM kv WHERE k = ?', args: [k] });
  if(!res.rows || !res.rows.length) return fallback;
  try { return JSON.parse(res.rows[0].v); } catch(e){ return fallback; }
}
async function kvSet(k, v){
  await turso.execute({
    sql: `INSERT INTO kv (k, v, updated_at) VALUES (?, ?, ?)
          ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at`,
    args: [k, JSON.stringify(v), Date.now()]
  });
}

/* Cache DB in memory for speed, flush to Turso on every write */
let DB = null;
async function loadDb(){
  DB = await kvGet('db', null);
  if(!DB){
    DB = require('./seed.json');
    await kvSet('db', DB);
    console.log('Database seeded');
  }
}
async function saveDb(){
  await kvSet('db', DB);
}

/* ---------- Sessions ---------- */
async function createSession(token, role, userId){
  await turso.execute({
    sql: 'INSERT INTO sessions (token, role, user_id, created_at) VALUES (?, ?, ?, ?)',
    args: [token, role, userId || '', Date.now()]
  });
}
async function getSession(token){
  const res = await turso.execute({
    sql: 'SELECT role, user_id, created_at FROM sessions WHERE token = ?',
    args: [token]
  });
  if(!res.rows || !res.rows.length) return null;
  return { role: res.rows[0].role, user_id: res.rows[0].user_id };
}
async function deleteSession(token){
  await turso.execute({ sql: 'DELETE FROM sessions WHERE token = ?', args: [token] });
}

/* ---------- Express ---------- */
const app = express();
app.use(cors());
app.use(express.json({ limit: '8mb' }));

function makeToken(){ return crypto.randomBytes(24).toString('hex'); }

function authRequired(roles){
  return async (req, res, next) => {
    const token = req.headers['x-auth-token'];
    if(!token) return res.status(401).json({ ok:false, error:'No token' });
    const sess = await getSession(token);
    if(!sess) return res.status(401).json({ ok:false, error:'Invalid session' });
    if(roles && roles.length && !roles.includes(sess.role)){
      return res.status(403).json({ ok:false, error:'Forbidden' });
    }
    req.session = sess;
    next();
  };
}

function publicDbFor(role, userId){
  const clone = JSON.parse(JSON.stringify(DB));
  if(clone.students) clone.students.forEach(s => { delete s.pin; });
  if(role === 'student'){
    clone.grades = (clone.grades || []).filter(g => g.studentId === userId);
    clone.tickets = (clone.tickets || []).filter(t => t.studentId === userId);
    clone.fees = (clone.fees || []).filter(f => f.studentId === userId);
    clone.attendance = (clone.attendance || []).filter(a => a.studentId === userId);
  }
  return clone;
}

/* ---------- Routes ---------- */
app.get('/', (req, res) => {
  res.json({ ok:true, app:'UON Portal Server', v:1, ts: Date.now() });
});

app.post('/api/login', async (req, res) => {
  try {
    const { role, userId, pin } = req.body || {};
    if(role === 'student'){
      const st = (DB.students || []).find(s => s.id === userId);
      if(!st) return res.status(404).json({ ok:false, error:'Student not found' });
      if(String(st.pin) !== String(pin)) return res.status(401).json({ ok:false, error:'Incorrect PIN' });
      const token = makeToken();
      await createSession(token, 'student', userId);
      return res.json({ ok:true, token, role:'student', userId });
    }
    if(role === 'teacher' || role === 'admin'){
      const serverPin = role === 'teacher'
        ? String(DB.teacherPin || '2222')
        : String(DB.adminPin || '3333');
      if(String(pin) !== serverPin) return res.status(401).json({ ok:false, error:'Incorrect PIN' });
      const token = makeToken();
      await createSession(token, role, userId || '');
      return res.json({ ok:true, token, role });
    }
    res.status(400).json({ ok:false, error:'Invalid role' });
  } catch(e){ res.status(500).json({ ok:false, error: e.message }); }
});

app.post('/api/logout', authRequired(), async (req, res) => {
  await deleteSession(req.headers['x-auth-token']);
  res.json({ ok:true });
});

app.get('/api/snapshot', authRequired(), (req, res) => {
  res.json({ ok:true, data: publicDbFor(req.session.role, req.session.user_id), ts: Date.now() });
});

app.post('/api/attendance', authRequired(['teacher','admin']), async (req, res) => {
  const { classId, studentId, date, status } = req.body || {};
  if(!classId || !studentId || !date || !status){
    return res.status(400).json({ ok:false, error:'Missing fields' });
  }
  DB.attendance = DB.attendance || [];
  const existing = DB.attendance.find(a =>
    a.classId === classId && a.studentId === studentId && a.date === date
  );
  if(existing){ existing.status = status; existing.ts = Date.now(); }
  else {
    DB.attendance.push({
      id: 'a_' + Date.now().toString(36) + Math.random().toString(36).slice(2,7),
      classId, studentId, date, status, ts: Date.now(), photo: null
    });
  }
  await saveDb();
  res.json({ ok:true });
});

app.post('/api/attendance/self', authRequired(['student']), async (req, res) => {
  const { classId, photo } = req.body || {};
  if(!classId) return res.status(400).json({ ok:false, error:'Missing class' });
  DB.attendance = DB.attendance || [];
  const date = new Date().toISOString().slice(0,10);
  const existing = DB.attendance.find(a =>
    a.classId === classId && a.studentId === req.session.user_id && a.date === date
  );
  if(existing){
    existing.status = 'present';
    existing.photo = photo || existing.photo;
    existing.ts = Date.now();
  } else {
    DB.attendance.push({
      id: 'a_' + Date.now().toString(36) + Math.random().toString(36).slice(2,7),
      classId, studentId: req.session.user_id, date, status:'present',
      ts: Date.now(), photo: photo || null
    });
  }
  await saveDb();
  res.json({ ok:true });
});

app.post('/api/grade', authRequired(['teacher','admin']), async (req, res) => {
  const { studentId, classId, marks, total, credits } = req.body || {};
  DB.grades = DB.grades || [];
  const existing = DB.grades.find(g => g.studentId === studentId && g.classId === classId);
  if(existing){
    existing.marks = marks; existing.total = total || 100;
    if(credits) existing.credits = credits;
  } else {
    DB.grades.push({
      id:'g_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7),
      studentId, classId, marks, total: total || 100, credits: credits || 3
    });
  }
  await saveDb();
  res.json({ ok:true });
});

app.post('/api/ticket', authRequired(['student']), async (req, res) => {
  const { subject, body } = req.body || {};
  if(!subject || !body) return res.status(400).json({ ok:false, error:'Missing fields' });
  DB.tickets = DB.tickets || [];
  DB.tickets.push({
    id:'k_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7),
    studentId: req.session.user_id, subject, body,
    status:'pending', date: new Date().toISOString().slice(0,10), reply:''
  });
  await saveDb();
  res.json({ ok:true });
});

app.post('/api/ticket/resolve', authRequired(['admin']), async (req, res) => {
  const { ticketId, reply } = req.body || {};
  const t = (DB.tickets || []).find(x => x.id === ticketId);
  if(!t) return res.status(404).json({ ok:false, error:'Not found' });
  t.status = 'resolved';
  t.reply = reply || 'Resolved by administration.';
  await saveDb();
  res.json({ ok:true });
});

app.post('/api/announcement', authRequired(['admin']), async (req, res) => {
  const { title, body, audience, signature } = req.body || {};
  if(!title || !body) return res.status(400).json({ ok:false, error:'Missing fields' });
  DB.announcements = DB.announcements || [];
  DB.announcements.push({
    id:'n_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7),
    title, body, audience: audience || 'all',
    date: new Date().toISOString().slice(0,10),
    author: 'Administration', signature: signature || null
  });
  await saveDb();
  res.json({ ok:true });
});

app.delete('/api/announcement/:id', authRequired(['admin']), async (req, res) => {
  DB.announcements = (DB.announcements || []).filter(a => a.id !== req.params.id);
  await saveDb();
  res.json({ ok:true });
});

app.post('/api/notice', authRequired(['teacher','admin']), async (req, res) => {
  const { classId, title, body, signature, signedBy } = req.body || {};
  if(!classId || !title || !body) return res.status(400).json({ ok:false, error:'Missing fields' });
  DB.notices = DB.notices || [];
  DB.notices.push({
    id:'cn_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7),
    classId, title, body,
    date: new Date().toISOString().slice(0,10),
    teacherId: req.session.user_id,
    signature: signature || null, signedBy: signedBy || null
  });
  await saveDb();
  res.json({ ok:true });
});

app.post('/api/signature', authRequired(['admin','teacher']), async (req, res) => {
  const { target, data: sigData, name } = req.body || {};
  DB.signatures = DB.signatures || {
    registrar:{data:null,name:'Registrar'},
    controller:{data:null,name:'Controller of Examinations'},
    admin:{data:null,name:''}
  };
  if(target === 'registrar' || target === 'controller' || target === 'admin'){
    DB.signatures[target] = { data: sigData, name: name || DB.signatures[target].name };
  } else if(target === 'teacher'){
    const t = (DB.teachers || []).find(x => x.id === req.session.user_id);
    if(t) t.signature = sigData;
  }
  await saveDb();
  res.json({ ok:true });
});

app.post('/api/students', authRequired(['admin']), async (req, res) => {
  DB.students = DB.students || [];
  const s = req.body;
  if(!s.id) s.id = 's_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7);
  const idx = DB.students.findIndex(x => x.id === s.id);
  if(idx >= 0) DB.students[idx] = Object.assign({}, DB.students[idx], s);
  else DB.students.push(s);
  await saveDb();
  res.json({ ok:true, id: s.id });
});

app.delete('/api/students/:id', authRequired(['admin']), async (req, res) => {
  DB.students = (DB.students || []).filter(s => s.id !== req.params.id);
  DB.attendance = (DB.attendance || []).filter(a => a.studentId !== req.params.id);
  DB.grades = (DB.grades || []).filter(g => g.studentId !== req.params.id);
  await saveDb();
  res.json({ ok:true });
});

app.post('/api/classes', authRequired(['admin']), async (req, res) => {
  DB.classes = DB.classes || [];
  const c = req.body;
  if(!c.id) c.id = 'c_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7);
  const idx = DB.classes.findIndex(x => x.id === c.id);
  if(idx >= 0) DB.classes[idx] = Object.assign({}, DB.classes[idx], c);
  else DB.classes.push(c);
  await saveDb();
  res.json({ ok:true, id: c.id });
});

app.delete('/api/classes/:id', authRequired(['admin']), async (req, res) => {
  DB.classes = (DB.classes || []).filter(c => c.id !== req.params.id);
  await saveDb();
  res.json({ ok:true });
});

/* ---------- Boot ---------- */
initTables().then(loadDb).then(() => {
  app.listen(PORT, () => {
    console.log('UON Portal Server listening on port ' + PORT);
    console.log('Connected to Turso: ' + TURSO_URL);
  });
}).catch(err => {
  console.error('Boot failed:', err);
  process.exit(1);
});