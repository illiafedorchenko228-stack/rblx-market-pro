require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!process.env.DATABASE_URL || !JWT_SECRET) {
  console.error('Missing DATABASE_URL or JWT_SECRET environment variable.');
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 40, standardHeaders: 'draft-7', legacyHeaders: false }));

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY, username VARCHAR(24) UNIQUE NOT NULL,
      email VARCHAR(254) UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      role VARCHAR(10) NOT NULL DEFAULT 'USER', balance BIGINT NOT NULL DEFAULT 1000000,
      bio VARCHAR(240) NOT NULL DEFAULT '', avatar_color VARCHAR(20) NOT NULL DEFAULT '#7657ff',
      blocked BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS products (
      id BIGSERIAL PRIMARY KEY, seller_id BIGINT NOT NULL REFERENCES users(id),
      title VARCHAR(100) NOT NULL, description VARCHAR(500) NOT NULL DEFAULT '',
      category VARCHAR(40) NOT NULL DEFAULT 'Items', price BIGINT NOT NULL CHECK(price > 0),
      status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS trades (
      id BIGSERIAL PRIMARY KEY, creator_id BIGINT NOT NULL REFERENCES users(id),
      target_username VARCHAR(24) NOT NULL DEFAULT '', offered_item VARCHAR(120) NOT NULL,
      requested_item VARCHAR(120) NOT NULL, note VARCHAR(300) NOT NULL DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'OPEN', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY, sender_id BIGINT NOT NULL REFERENCES users(id),
      recipient_id BIGINT NOT NULL REFERENCES users(id), body VARCHAR(1000) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS tickets (
      id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id),
      subject VARCHAR(120) NOT NULL, body VARCHAR(2000) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'OPEN', admin_reply VARCHAR(2000) NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id BIGSERIAL PRIMARY KEY, admin_id BIGINT REFERENCES users(id),
      action VARCHAR(80) NOT NULL, details VARCHAR(1000) NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS messages_pair_idx ON messages(sender_id, recipient_id, id);
    CREATE INDEX IF NOT EXISTS products_status_idx ON products(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS tickets_status_idx ON tickets(status, updated_at DESC);
  `);
}
function safeUser(u) {
  return { id: u.id, username: u.username, email: u.email, role: u.role, balance: Number(u.balance), bio: u.bio, avatarColor: u.avatar_color, blocked: u.blocked, createdAt: u.created_at };
}
function tokenFor(user) { return jwt.sign({ id: String(user.id) }, JWT_SECRET, { expiresIn: '7d' }); }
async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  try {
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [payload.id]);
    if (!rows[0]) return res.status(401).json({ error: 'Please sign in.' });
    if (rows[0].blocked) return res.status(403).json({ error: 'This account is blocked.' });
    req.user = rows[0]; next();
  } catch { return res.status(401).json({ error: 'Please sign in again.' }); }
}
function admin(req, res, next) { if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin access required.' }); next(); }
function clean(s, max=500) { return String(s ?? '').trim().slice(0, max); }
async function logAdmin(adminId, action, details) { await pool.query('INSERT INTO audit_log(admin_id,action,details) VALUES($1,$2,$3)', [adminId, action, clean(details,1000)]); }

// The app's static files live in the repository root; no public/ folder is required.
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/style.css', (_req, res) => res.sendFile(path.join(__dirname, 'style.css')));
app.get('/app.js', (_req, res) => res.sendFile(path.join(__dirname, 'app.js')));
app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});

app.post('/api/auth/register', async (req,res) => {
  try {
    const username = clean(req.body.username,24), email = clean(req.body.email,254).toLowerCase(), password = String(req.body.password || '');
    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) return res.status(400).json({error:'Username must be 3–24 letters, numbers or underscores.'});
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'Enter a valid email.'});
    if (password.length < 8 || password.length > 128) return res.status(400).json({error:'Password must be 8–128 characters.'});
    const role = process.env.ADMIN_EMAIL && email === process.env.ADMIN_EMAIL.trim().toLowerCase() ? 'ADMIN' : 'USER';
    const hash = await bcrypt.hash(password, 12);
    const {rows} = await pool.query('INSERT INTO users(username,email,password_hash,role,balance) VALUES($1,$2,$3,$4,1000000) RETURNING *', [username,email,hash,role]);
    res.status(201).json({token:tokenFor(rows[0]), user:safeUser(rows[0])});
  } catch(e) { if (e.code==='23505') return res.status(409).json({error:'Email or username is already registered.'}); console.error(e); res.status(500).json({error:'Could not create account.'}); }
});
app.post('/api/auth/login', async (req,res) => {
  try {
    const email=clean(req.body.email,254).toLowerCase(), password=String(req.body.password||'');
    const {rows}=await pool.query('SELECT * FROM users WHERE email=$1',[email]);
    if (!rows[0] || !(await bcrypt.compare(password,rows[0].password_hash))) return res.status(401).json({error:'Incorrect email or password.'});
    if (rows[0].blocked) return res.status(403).json({error:'This account is blocked.'});
    res.json({token:tokenFor(rows[0]),user:safeUser(rows[0])});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not sign in.'}); }
});
app.get('/api/me',auth,(req,res)=>res.json({user:safeUser(req.user)}));
app.patch('/api/me',auth,async(req,res)=>{
  const bio=clean(req.body.bio,240), avatar=clean(req.body.avatarColor,20);
  const color=/^#[0-9a-fA-F]{6}$/.test(avatar)?avatar:req.user.avatar_color;
  const {rows}=await pool.query('UPDATE users SET bio=$1,avatar_color=$2 WHERE id=$3 RETURNING *',[bio,color,req.user.id]); res.json({user:safeUser(rows[0])});
});
app.get('/api/products',async(req,res)=>{
  try { const q=clean(req.query.q,80), cat=clean(req.query.category,40); const {rows}=await pool.query(`SELECT p.id,p.title,p.description,p.category,p.price,p.status,p.created_at,u.username AS seller FROM products p JOIN users u ON u.id=p.seller_id WHERE p.status='ACTIVE' AND ($1='' OR p.title ILIKE '%'||$1||'%' OR p.description ILIKE '%'||$1||'%') AND ($2='' OR p.category=$2) ORDER BY p.created_at DESC LIMIT 100`,[q,cat]); res.json({products:rows.map(p=>({...p,price:Number(p.price)}))}); } catch(e){console.error(e);res.status(500).json({error:'Could not load listings.'});}
});
app.post('/api/products',auth,async(req,res)=>{
  const title=clean(req.body.title,100), description=clean(req.body.description,500), category=clean(req.body.category,40)||'Items', price=Number(req.body.price);
  if(title.length<3||!Number.isSafeInteger(price)||price<1||price>100000000) return res.status(400).json({error:'Enter a title (at least 3 characters) and a valid positive price.'});
  const {rows}=await pool.query('INSERT INTO products(seller_id,title,description,category,price) VALUES($1,$2,$3,$4,$5) RETURNING *',[req.user.id,title,description,category,price]);res.status(201).json({product:rows[0]});
});
app.post('/api/products/:id/buy',auth,async(req,res)=>{
  const client=await pool.connect(); try { await client.query('BEGIN'); const {rows}=await client.query("SELECT * FROM products WHERE id=$1 AND status='ACTIVE' FOR UPDATE",[req.params.id]); const p=rows[0]; if(!p) throw new Error('Listing is no longer available.'); if(String(p.seller_id)===String(req.user.id)) throw new Error('You cannot buy your own listing.'); const {rows:buyers}=await client.query('SELECT * FROM users WHERE id=$1 FOR UPDATE',[req.user.id]); if(Number(buyers[0].balance)<Number(p.price)) throw new Error('Not enough demo balance.'); await client.query('UPDATE users SET balance=balance-$1 WHERE id=$2',[p.price,req.user.id]); await client.query('UPDATE users SET balance=balance+$1 WHERE id=$2',[p.price,p.seller_id]); await client.query("UPDATE products SET status='SOLD' WHERE id=$1",[p.id]); await client.query('COMMIT'); const {rows:u}=await pool.query('SELECT * FROM users WHERE id=$1',[req.user.id]); res.json({ok:true,user:safeUser(u[0])}); } catch(e){await client.query('ROLLBACK');res.status(400).json({error:e.message||'Purchase failed.'});} finally{client.release();}
});
app.get('/api/trades',auth,async(req,res)=>{const {rows}=await pool.query("SELECT t.*,u.username AS creator FROM trades t JOIN users u ON u.id=t.creator_id WHERE t.status='OPEN' ORDER BY t.created_at DESC LIMIT 100");res.json({trades:rows});});
app.post('/api/trades',auth,async(req,res)=>{const offered=clean(req.body.offeredItem,120),requested=clean(req.body.requestedItem,120),target=clean(req.body.targetUsername,24),note=clean(req.body.note,300);if(offered.length<2||requested.length<2)return res.status(400).json({error:'Describe both items.'});const {rows}=await pool.query('INSERT INTO trades(creator_id,target_username,offered_item,requested_item,note) VALUES($1,$2,$3,$4,$5) RETURNING *',[req.user.id,target,offered,requested,note]);res.status(201).json({trade:rows[0]});});
app.post('/api/trades/:id/close',auth,async(req,res)=>{const {rows}=await pool.query("UPDATE trades SET status='CLOSED' WHERE id=$1 AND creator_id=$2 AND status='OPEN' RETURNING *",[req.params.id,req.user.id]);if(!rows[0])return res.status(404).json({error:'Trade not found or you do not own it.'});res.json({trade:rows[0]});});
app.get('/api/users',auth,async(req,res)=>{const {rows}=await pool.query('SELECT id,username FROM users WHERE blocked=false AND id<>$1 ORDER BY username LIMIT 100',[req.user.id]);res.json({users:rows});});
app.get('/api/messages/:username',auth,async(req,res)=>{const name=clean(req.params.username,24);const {rows:u}=await pool.query('SELECT id FROM users WHERE username=$1',[name]);if(!u[0])return res.status(404).json({error:'User not found.'});const {rows}=await pool.query('SELECT m.id,m.body,m.created_at,u.username AS sender FROM messages m JOIN users u ON u.id=m.sender_id WHERE (m.sender_id=$1 AND m.recipient_id=$2) OR (m.sender_id=$2 AND m.recipient_id=$1) ORDER BY m.id ASC LIMIT 200',[req.user.id,u[0].id]);res.json({messages:rows});});
app.post('/api/messages',auth,async(req,res)=>{const to=clean(req.body.to,24),body=clean(req.body.body,1000);if(!body)return res.status(400).json({error:'Message cannot be empty.'});const {rows:u}=await pool.query('SELECT id FROM users WHERE username=$1 AND blocked=false',[to]);if(!u[0])return res.status(404).json({error:'Recipient not found.'});const {rows}=await pool.query('INSERT INTO messages(sender_id,recipient_id,body) VALUES($1,$2,$3) RETURNING id,body,created_at',[req.user.id,u[0].id,body]);res.status(201).json({message:rows[0]});});
app.get('/api/tickets',auth,async(req,res)=>{const isAdmin=req.user.role==='ADMIN';const {rows}=await pool.query(`SELECT t.*,u.username FROM tickets t JOIN users u ON u.id=t.user_id ${isAdmin?'':'WHERE t.user_id=$1'} ORDER BY t.updated_at DESC LIMIT 100`,isAdmin?[]:[req.user.id]);res.json({tickets:rows});});
app.post('/api/tickets',auth,async(req,res)=>{const subject=clean(req.body.subject,120),body=clean(req.body.body,2000);if(subject.length<3||body.length<5)return res.status(400).json({error:'Enter a subject and a message.'});const {rows}=await pool.query('INSERT INTO tickets(user_id,subject,body) VALUES($1,$2,$3) RETURNING *',[req.user.id,subject,body]);res.status(201).json({ticket:rows[0]});});
app.patch('/api/tickets/:id',auth,admin,async(req,res)=>{const status=['OPEN','IN_PROGRESS','CLOSED'].includes(req.body.status)?req.body.status:'IN_PROGRESS';const reply=clean(req.body.adminReply,2000);const {rows}=await pool.query('UPDATE tickets SET status=$1,admin_reply=$2,updated_at=NOW() WHERE id=$3 RETURNING *',[status,reply,req.params.id]);if(!rows[0])return res.status(404).json({error:'Ticket not found.'});await logAdmin(req.user.id,'ticket_update',`ticket=${req.params.id}; status=${status}`);res.json({ticket:rows[0]});});
app.get('/api/admin/users',auth,admin,async(req,res)=>{const {rows}=await pool.query('SELECT id,username,email,role,balance,blocked,created_at FROM users ORDER BY created_at DESC LIMIT 300');res.json({users:rows.map(u=>({...u,balance:Number(u.balance)}))});});
app.patch('/api/admin/users/:id',auth,admin,async(req,res)=>{const blocked=Boolean(req.body.blocked);if(String(req.params.id)===String(req.user.id)&&blocked)return res.status(400).json({error:'You cannot block your own account.'});const {rows}=await pool.query('UPDATE users SET blocked=$1 WHERE id=$2 RETURNING id,username,email,role,balance,blocked',[blocked,req.params.id]);if(!rows[0])return res.status(404).json({error:'User not found.'});await logAdmin(req.user.id,blocked?'user_block':'user_unblock',`user=${req.params.id}`);res.json({user:rows[0]});});
app.get('/api/admin/logs',auth,admin,async(req,res)=>{const {rows}=await pool.query('SELECT a.*,u.username AS admin_username FROM audit_log a LEFT JOIN users u ON u.id=a.admin_id ORDER BY a.id DESC LIMIT 100');res.json({logs:rows});});
app.use('/api',(_req,res)=>res.status(404).json({error:'API route not found.'}));
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Unexpected server error.'});});

initDb().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`RBLX Market listening on port ${PORT}`))).catch(e=>{console.error('Database initialization failed:',e.message);process.exit(1);});
