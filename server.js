/* =========================================================
   UON Portal — Sync Server
   Node.js + Express + JSON file storage (no native deps)
   ========================================================= */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'uon.db.json');
const SESS_PATH = path.join(path.dirname(DB_PATH), 'uon-sessions.json');

/* ---------- Simple JSON store ---------- */
function readJson(file, fallback){
  try {
    if(!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch(e){
    console.error('read error', file, e.message);
    return fallback;
  }
}
function writeJson(file, obj){
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(obj, null, 2));
  } catch(e){
    console.error('write error', file, e.message);
  }
}

let DB = readJson(DB_PATH, null);
if(!DB){
  const seed = require('./seed.json');
  DB = seed;
  writeJson(DB_PATH, DB);
  console.log('Database seeded with initial data');
}

let SESSIONS = readJson(SESS_PATH, {});
function saveSessions(){ writeJson(SESS_PATH, SESSIONS); }

function getDb(){ return DB; }
function setDb(d){ DB = d; writeJson(DB_PATH, DB); }

/* ---------- Express setup ---------- */
const app = express();
app.use(cors());
app.use(express.json({ limit: '8mb' }));

function makeToken(){
  return crypto.randomBytes(24).toString('hex');
}

function authRequired(roles){
  return (req, res, next) => {
    const token = req.headers['x-auth-token'];
    if(!token) return res.status(401).json({ ok:false, error:'No token' });
    const sess = SESSIONS[token];
    if(!sess) return res.status(401).json({ ok:false, error:'Invalid session' });
    if(roles && roles.length && !roles.includes(sess.role)){
      return res.status(403).json({ ok:false, error:'Forbidden' });
    }
    req.session = sess;
    next();
  };
}

function publicDbFor(role, userId){
  const data = getDb();
  const clone = JSON.parse(JSON.stringify(data));
  if(clone.students){
    clone.students.forEach(s => { delete s.pin; });
  }
  if(role === 'student'){
    clone.grades = (clone.grades || []).filter(g => g.studentId === userId);
    clone.tickets = (clone.tickets || []).filter(t => t.studentId === userId);
    clone.fees = (clone.fees || []).filter(f => f.studentId === userId);
    clone.attendance = (clone.attendance || []).filter(a => a.studentId === userId);
  }
  return clone;
}

/* ---------- Health ---------- */
app.get('/', (req, res) => {
  res.json({ ok:true, app:'UON Portal Server', v:1, ts: Date.now() });
});

/* ---------- Auth ---------- */
app.post('/api/login', (req, res) => {
  const { role, userId, pin } = req.body || {};
  const data = getDb();

  if(role === 'student'){
    const st = (data.students || []).find(s => s.id === userId);
    if(!st) return res.status(404).json({ ok:false, error:'Student not found' });
    if(String(st.pin) !== String(pin)) return res.status(401).json({ ok:false, error:'Incorrect PIN' });
    const token = makeToken();
    SESSIONS[token] = { role:'student', user_id:userId, created_at: Date.now() };
    saveSessions();
    return res.json({ ok:true, token, role:'student', userId });
  }

  if(role === 'teacher' || role === 'admin'){
    const serverPin = role === 'teacher'
      ? String(data.teacherPin || '2222')
      : String(data.adminPin || '3333');
    if(String(pin) !== serverPin) return res.status(401).json({ ok:false, error:'Incorrect PIN' });
    const token = makeToken();
    SESSIONS[token] = { role, user_id:userId || '', created_at: Date.now() };
    saveSessions();
    return res.json({ ok:true, token, role });
  }

  res.status(400).json({ ok:false, error:'Invalid role' });
});

app.post('/api/logout', authRequired(), (req, res) => {
  delete SESSIONS[req.headers['x-auth-token']];
  saveSessions();
  res.json({ ok:true });
});

/* ---------- Snapshot ---------- */
app.get('/api/snapshot', authRequired(), (req, res) => {
  const sess = req.session;
  res.json({
    ok: true,
    data: publicDbFor(sess.role, sess.user_id),
    ts: Date.now()
  });
});

/* ---------- Attendance (teacher) ---------- */
app.post('/api/attendance', authRequired(['teacher','admin']), (req, res) => {
  const { classId, studentId, date, status } = req.body || {};
  if(!classId || !studentId || !date || !status){
    return res.status(400).json({ ok:false, error:'Missing fields' });
  }
  const data = getDb();
  data.attendance = data.attendance || [];
  const existing = data.attendance.find(a =>
    a.classId === classId && a.studentId === studentId && a.date === date
  );
  if(existing){
    existing.status = status;
    existing.ts = Date.now();
  } else {
    data.attendance.push({
      id: 'a_' + Date.now().toString(36) + Math.random().toString(36).slice(2,7),
      classId, studentId, date, status, ts: Date.now(), photo: null
    });
  }
  setDb(data);
  res.json({ ok:true, ts: Date.now() });
});

/* ---------- Attendance (student self-mark) ---------- */
app.post('/api/attendance/self', authRequired(['student']), (req, res) => {
  const { classId, photo } = req.body || {};
  if(!classId) return res.status(400).json({ ok:false, error:'Missing class' });
  const sess = req.session;
  const data = getDb();
  data.attendance = data.attendance || [];
  const date = new Date().toISOString().slice(0,10);
  const existing = data.attendance.find(a =>
    a.classId === classId && a.studentId === sess.user_id && a.date === date
  );
  if(existing){
    existing.status = 'present';
    existing.photo = photo || existing.photo;
    existing.ts = Date.now();
  } else {
    data.attendance.push({
      id: 'a_' + Date.now().toString(36) + Math.random().toString(36).slice(2,7),
      classId, studentId: sess.user_id, date, status:'present',
      ts: Date.now(), photo: photo || null
    });
  }
  setDb(data);
  res.json({ ok:true });
});

/* ---------- Grades ---------- */
app.post('/api/grade', authRequired(['teacher','admin']), (req, res) => {
  const { studentId, classId, marks, total, credits } = req.body || {};
  const data = getDb();
  data.grades = data.grades || [];
  const existing = data.grades.find(g => g.studentId === studentId && g.classId === classId);
  if(existing){
    existing.marks = marks;
    existing.total = total || 100;
    if(credits) existing.credits = credits;
  } else {
    data.grades.push({
      id:'g_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7),
      studentId, classId, marks, total: total || 100, credits: credits || 3
    });
  }
  setDb(data);
  res.json({ ok:true });
});

/* ---------- Tickets ---------- */
app.post('/api/ticket', authRequired(['student']), (req, res) => {
  const { subject, body } = req.body || {};
  if(!subject || !body) return res.status(400).json({ ok:false, error:'Missing fields' });
  const data = getDb();
  data.tickets = data.tickets || [];
  data.tickets.push({
    id:'k_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7),
    studentId: req.session.user_id,
    subject, body,
    status:'pending',
    date: new Date().toISOString().slice(0,10),
    reply:''
  });
  setDb(data);
  res.json({ ok:true });
});

app.post('/api/ticket/resolve', authRequired(['admin']), (req, res) => {
  const { ticketId, reply } = req.body || {};
  const data = getDb();
  const t = (data.tickets || []).find(x => x.id === ticketId);
  if(!t) return res.status(404).json({ ok:false, error:'Not found' });
  t.status = 'resolved';
  t.reply = reply || 'Resolved by administration.';
  setDb(data);
  res.json({ ok:true });
});

/* ---------- Announcements ---------- */
app.post('/api/announcement', authRequired(['admin']), (req, res) => {
  const { title, body, audience, signature } = req.body || {};
  if(!title || !body) return res.status(400).json({ ok:false, error:'Missing fields' });
  const data = getDb();
  data.announcements = data.announcements || [];
  data.announcements.push({
    id:'n_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7),
    title, body, audience: audience || 'all',
    date: new Date().toISOString().slice(0,10),
    author: 'Administration',
    signature: signature || null
  });
  setDb(data);
  res.json({ ok:true });
});

app.delete('/api/announcement/:id', authRequired(['admin']), (req, res) => {
  const data = getDb();
  data.announcements = (data.announcements || []).filter(a => a.id !== req.params.id);
  setDb(data);
  res.json({ ok:true });
});

/* ---------- Class notices ---------- */
app.post('/api/notice', authRequired(['teacher','admin']), (req, res) => {
  const { classId, title, body, signature, signedBy } = req.body || {};
  if(!classId || !title || !body) return res.status(400).json({ ok:false, error:'Missing fields' });
  const data = getDb();
  data.notices = data.notices || [];
  data.notices.push({
    id:'cn_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7),
    classId, title, body,
    date: new Date().toISOString().slice(0,10),
    teacherId: req.session.user_id,
    signature: signature || null,
    signedBy: signedBy || null
  });
  setDb(data);
  res.json({ ok:true });
});

/* ---------- Signatures ---------- */
app.post('/api/signature', authRequired(['admin','teacher']), (req, res) => {
  const { target, data: sigData, name } = req.body || {};
  const data = getDb();
  data.signatures = data.signatures || {
    registrar:{data:null,name:'Registrar'},
    controller:{data:null,name:'Controller of Examinations'},
    admin:{data:null,name:''}
  };
  if(target === 'registrar' || target === 'controller' || target === 'admin'){
    data.signatures[target] = { data: sigData, name: name || data.signatures[target].name };
  } else if(target === 'teacher'){
    const t = (data.teachers || []).find(x => x.id === req.session.user_id);
    if(t) t.signature = sigData;
  }
  setDb(data);
  res.json({ ok:true });
});

/* ---------- Admin CRUD ---------- */
app.post('/api/students', authRequired(['admin']), (req, res) => {
  const data = getDb();
  data.students = data.students || [];
  const s = req.body;
  if(!s.id) s.id = 's_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7);
  const idx = data.students.findIndex(x => x.id === s.id);
  if(idx >= 0) data.students[idx] = Object.assign({}, data.students[idx], s);
  else data.students.push(s);
  setDb(data);
  res.json({ ok:true, id: s.id });
});

app.delete('/api/students/:id', authRequired(['admin']), (req, res) => {
  const data = getDb();
  data.students = (data.students || []).filter(s => s.id !== req.params.id);
  data.attendance = (data.attendance || []).filter(a => a.studentId !== req.params.id);
  data.grades = (data.grades || []).filter(g => g.studentId !== req.params.id);
  setDb(data);
  res.json({ ok:true });
});

app.post('/api/classes', authRequired(['admin']), (req, res) => {
  const data = getDb();
  data.classes = data.classes || [];
  const c = req.body;
  if(!c.id) c.id = 'c_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7);
  const idx = data.classes.findIndex(x => x.id === c.id);
  if(idx >= 0) data.classes[idx] = Object.assign({}, data.classes[idx], c);
  else data.classes.push(c);
  setDb(data);
  res.json({ ok:true, id: c.id });
});

app.delete('/api/classes/:id', authRequired(['admin']), (req, res) => {
  const data = getDb();
  data.classes = (data.classes || []).filter(c => c.id !== req.params.id);
  setDb(data);
  res.json({ ok:true });
});

/* ---------- Cleanup old sessions ---------- */
setInterval(() => {
  const cutoff = Date.now() - 30*24*60*60*1000;
  let changed = false;
  Object.keys(SESSIONS).forEach(tok => {
    if(SESSIONS[tok].created_at < cutoff){ delete SESSIONS[tok]; changed = true; }
  });
  if(changed) saveSessions();
}, 60*60*1000);

app.listen(PORT, () => {
  console.log('UON Portal Server listening on port ' + PORT);
  console.log('Storage file: ' + DB_PATH);
});