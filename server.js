const express = require('express');
const path = require('path');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(cors({
  origin: 'https://gbairai.netlify.app',  // <-- remplace par ton vrai domaine Netlify
  credentials: true
}));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // vrai en prod (HTTPS)
    sameSite: 'none', // nécessaire pour cross-site cookies
    httpOnly: true
  }
}));

const connectionString = process.env.DATABASE_URL || null;
let pool = null;
if (connectionString) {
  pool = new Pool({
    connectionString,
    ssl: (process.env.NODE_ENV === 'production') ? { rejectUnauthorized: false } : false
  });
}

let inMemory = {
  users: [],
  posts: [],
  zones: [],
  nextPostId: 1
};

async function ensureTables() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS zones (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      content TEXT NOT NULL,
      zone TEXT,
      likes INT DEFAULT 0,
      dislikes INT DEFAULT 0,
      liked_by JSONB DEFAULT '[]',
      disliked_by JSONB DEFAULT '[]',
      comments JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT now()
    );
  `);
}

(async()=>{ try { await ensureTables(); console.log('DB ready'); } catch(e){ console.warn('DB not ready or not used:', e.message); } })();

function sendServerError(res, e){
  console.error(e);
  return res.status(500).json({ error: 'server_error', message: e.message || String(e) });
}

function rowToPost(row){
  return {
    id: row.id,
    user: row.username,
    content: row.content,
    zone: row.zone,
    likes: +row.likes || 0,
    dislikes: +row.dislikes || 0,
    likedBy: row.liked_by || [],
    dislikedBy: row.disliked_by || [],
    comments: row.comments || [],
    created_at: row.created_at
  };
}

// LOGIN / REGISTER
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success:false, message:'username & password required' });

    if (!pool) {
      let u = inMemory.users.find(x=>x.username===username);
      if(!u){
        const hash = bcrypt.hashSync(password, 10);
        u = { username, password: hash };
        inMemory.users.push(u);
      } else {
        if (!bcrypt.compareSync(password, u.password)) return res.status(401).json({ success:false, message: 'invalid credentials' });
      }
      req.session.username = username;
      return res.json({ success:true, user: { username } });
    }

    const r = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (r.rowCount === 0) {
      const hash = bcrypt.hashSync(password, 10);
      await pool.query('INSERT INTO users (username, password) VALUES ($1,$2)', [username, hash]);
      req.session.username = username;
      return res.json({ success:true, user: { username } });
    } else {
      const user = r.rows[0];
      if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success:false, message:'invalid credentials' });
      req.session.username = username;
      return res.json({ success:true, user: { username } });
    }
  } catch(e){ return sendServerError(res, e); }
});

app.get('/api/me', (req,res) => {
  if (req.session && req.session.username) return res.json({ username: req.session.username });
  return res.status(401).json({ error: 'not_logged_in' });
});

// ZONES
app.get('/api/zones', async (req,res) => {
  try {
    if (!pool) return res.json(inMemory.zones);
    const r = await pool.query('SELECT name FROM zones ORDER BY name');
    return res.json(r.rows.map(r=>r.name));
  } catch(e){ return sendServerError(res,e); }
});

app.post('/api/zones', async (req,res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error:'missing_name' });
    if (!pool) {
      if (!inMemory.zones.includes(name)) inMemory.zones.push(name);
      return res.json({ name });
    }
    const r = await pool.query('INSERT INTO zones (name) VALUES ($1) ON CONFLICT (name) DO NOTHING RETURNING name', [name]);
    if (r.rowCount === 0) return res.status(409).json({ error:'already_exists', name });
    return res.json({ name: r.rows[0].name });
  } catch(e){ return sendServerError(res,e); }
});

// POSTS
app.get('/api/posts', async (req,res) => {
  try {
    if (!pool) return res.json(inMemory.posts.slice().reverse());
    const r = await pool.query('SELECT * FROM posts ORDER BY id DESC');
    return res.json(r.rows.map(rowToPost));
  } catch(e){ return sendServerError(res,e); }
});

app.post('/api/posts', async (req,res) => {
  try {
    const username = (req.session && req.session.username) || req.body.user;
    if (!username) return res.status(401).json({ error:'not_logged_in' });
    const { content, zone } = req.body;
    if (!content || !content.trim()) return res.status(400).json({ error:'empty_content' });

    if (!pool) {
      const post = {
        id: inMemory.nextPostId++,
        user: username,
        content,
        zone: zone || null,
        likes: 0, dislikes: 0, likedBy: [], dislikedBy: [], comments: [], created_at: new Date().toISOString()
      };
      inMemory.posts.push(post);
      return res.json(post);
    }

    const r = await pool.query(
      `INSERT INTO posts (username, content, zone, likes, dislikes, liked_by, disliked_by, comments)
       VALUES ($1,$2,$3,0,0,'[]','[]','[]') RETURNING *`,
      [username, content, zone || null]
    );
    return res.json(rowToPost(r.rows[0]));
  } catch(e){ return sendServerError(res,e); }
});

app.put('/api/posts/:id', async (req,res) => {
  try {
    const id = +req.params.id;
    const username = req.session && req.session.username;
    if (!username) return res.status(401).json({ error:'not_logged_in' });
    const { content } = req.body;
    if (!content) return res.status(400).json({ error:'missing_content' });

    if (!pool) {
      const p = inMemory.posts.find(x=>x.id===id);
      if (!p) return res.status(404).json({ error:'not_found' });
      if (p.user !== username) return res.status(403).json({ error:'forbidden' });
      p.content = content;
      return res.json(p);
    }

    const cur = await pool.query('SELECT * FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error:'not_found' });
    if (cur.rows[0].username !== username) return res.status(403).json({ error:'forbidden' });

    const updated = await pool.query('UPDATE posts SET content=$1 WHERE id=$2 RETURNING *', [content, id]);
    return res.json(rowToPost(updated.rows[0]));
  } catch(e){ return sendServerError(res,e); }
});

app.delete('/api/posts/:id', async (req,res) => {
  try {
    const id = +req.params.id;
    const username = req.session && req.session.username;
    if (!username) return res.status(401).json({ error:'not_logged_in' });

    if (!pool) {
      const idx = inMemory.posts.findIndex(x=>x.id===id);
      if (idx === -1) return res.status(404).json({ error:'not_found' });
      if (inMemory.posts[idx].user !== username) return res.status(403).json({ error:'forbidden' });
      inMemory.posts.splice(idx,1);
      return res.json({ success:true });
    }

    const cur = await pool.query('SELECT * FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error:'not_found' });
    if (cur.rows[0].username !== username) return res.status(403).json({ error:'forbidden' });

    await pool.query('DELETE FROM posts WHERE id=$1', [id]);
    return res.json({ success:true });
  } catch(e){ return sendServerError(res,e); }
});

// COMMENTS
app.post('/api/posts/:id/comments', async (req,res) => {
  try {
    const id = +req.params.id;
    const username = (req.session && req.session.username) || req.body.user;
    if (!username) return res.status(401).json({ error:'not_logged_in' });
    const text = (req.body.text || '').trim();
    if (!text) return res.status(400).json({ error:'empty_comment' });

    if (!pool) {
      const post = inMemory.posts.find(x=>x.id===id);
      if(!post) return res.status(404).json({ error:'not_found' });
      post.comments = post.comments || [];
      post.comments.push({ user: username, text });
      return res.json(post);
    }

    const cur = await pool.query('SELECT comments FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error:'not_found' });
    const comments = cur.rows[0].comments || [];
    comments.push({ user: username, text, created_at: new Date().toISOString() });
    const updated = await pool.query('UPDATE posts SET comments=$1 WHERE id=$2 RETURNING *', [JSON.stringify(comments), id]);
    return res.json(rowToPost(updated.rows[0]));
  } catch(e){ return sendServerError(res,e); }
});

app.delete('/api/posts/:id/comments/:idx', async (req,res) => {
  try {
    const id = +req.params.id;
    const idx = +req.params.idx;
    const username = req.session && req.session.username;
    if (!username) return res.status(401).json({ error:'not_logged_in' });

    if (!pool) {
      const post = inMemory.posts.find(x=>x.id===id);
      if(!post) return res.status(404).json({ error:'not_found' });
      if(!post.comments || !post.comments[idx]) return res.status(404).json({ error:'not_found' });
      if (post.comments[idx].user !== username) return res.status(403).json({ error:'forbidden' });
      post.comments.splice(idx,1);
      return res.json(post);
    }

    const cur = await pool.query('SELECT comments FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error:'not_found' });
    const comments = cur.rows[0].comments || [];
    if (!comments[idx]) return res.status(404).json({ error:'not_found' });
    if (comments[idx].user !== username) return res.status(403).json({ error:'forbidden' });

    comments.splice(idx,1);
    const updated = await pool.query('UPDATE posts SET comments=$1 WHERE id=$2 RETURNING *', [JSON.stringify(comments), id]);
    return res.json(rowToPost(updated.rows[0]));
  } catch(e){ return sendServerError(res,e); }
});

// LIKE / DISLIKE
app.post('/api/posts/:id/like', async (req,res) => {
  try {
    const id = +req.params.id;
    const username = req.session && req.session.username;
    if (!username) return res.status(401).json({ error:'not_logged_in' });

    if (!pool) {
      const post = inMemory.posts.find(x=>x.id===id);
      if(!post) return res.status(404).json({ error:'not_found' });
      post.likedBy = post.likedBy || [];
      post.dislikedBy = post.dislikedBy || [];
      if (post.likedBy.includes(username)) {
        post.likedBy = post.likedBy.filter(u=>u!==username);
        post.likes = Math.max(0, (post.likes||0)-1);
      } else {
        post.likedBy.push(username);
        post.likes = (post.likes||0)+1;
        if (post.dislikedBy.includes(username)) {
          post.dislikedBy = post.dislikedBy.filter(u=>u!==username);
          post.dislikes = Math.max(0, (post.dislikes||0)-1);
        }
      }
      return res.json(post);
    }

    const cur = await pool.query('SELECT liked_by, disliked_by, likes, dislikes FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error:'not_found' });
    let liked = cur.rows[0].liked_by || [];
    let disliked = cur.rows[0].disliked_by || [];
    let likes = +cur.rows[0].likes||0;
    let dislikes = +cur.rows[0].dislikes||0;

    if (liked.includes(username)) {
      liked = liked.filter(u=>u!==username); likes = Math.max(0, likes-1);
    } else {
      liked.push(username); likes = likes+1;
      if (disliked.includes(username)) {
        disliked = disliked.filter(u=>u!==username); dislikes = Math.max(0, dislikes-1);
      }
    }
    const updated = await pool.query(
      'UPDATE posts SET liked_by=$1, disliked_by=$2, likes=$3, dislikes=$4 WHERE id=$5 RETURNING *',
      [JSON.stringify(liked), JSON.stringify(disliked), likes, dislikes, id]
    );
    return res.json(rowToPost(updated.rows[0]));
  } catch(e){ return sendServerError(res,e); }
});

app.post('/api/posts/:id/dislike', async (req,res) => {
  try {
    const id = +req.params.id;
    const username = req.session && req.session.username;
    if (!username) return res.status(401).json({ error:'not_logged_in' });

    if (!pool) {
      const post = inMemory.posts.find(x=>x.id===id);
      if(!post) return res.status(404).json({ error:'not_found' });
      post.likedBy = post.likedBy || [];
      post.dislikedBy = post.dislikedBy || [];
      if (post.dislikedBy.includes(username)) {
        post.dislikedBy = post.dislikedBy.filter(u=>u!==username);
        post.dislikes = Math.max(0, (post.dislikes||0)-1);
      } else {
        post.dislikedBy.push(username);
        post.dislikes = (post.dislikes||0)+1;
        if (post.likedBy.includes(username)) {
          post.likedBy = post.likedBy.filter(u=>u!==username);
          post.likes = Math.max(0, (post.likes||0)-1);
        }
      }
      return res.json(post);
    }

    const cur = await pool.query('SELECT liked_by, disliked_by, likes, dislikes FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error:'not_found' });
    let liked = cur.rows[0].liked_by || [];
    let disliked = cur.rows[0].disliked_by || [];
    let likes = +cur.rows[0].likes||0;
    let dislikes = +cur.rows[0].dislikes||0;

    if (disliked.includes(username)) {
      disliked = disliked.filter(u=>u!==username); dislikes = Math.max(0, dislikes-1);
    } else {
      disliked.push(username); dislikes = dislikes+1;
      if (liked.includes(username)) {
        liked = liked.filter(u=>u!==username); likes = Math.max(0, likes-1);
      }
    }
    const updated = await pool.query(
      'UPDATE posts SET liked_by=$1, disliked_by=$2, likes=$3, dislikes=$4 WHERE id=$5 RETURNING *',
      [JSON.stringify(liked), JSON.stringify(disliked), likes, dislikes, id]
    );
    return res.json(rowToPost(updated.rows[0]));
  } catch(e){ return sendServerError(res,e); }
});
// Catch-all pour les requêtes non-API
app.use((req, res) => {
  res.status(404).json({ error: 'not_found', message: 'Cette route n\'existe pas ou n\'est pas une API.' });
});
// Définit le port (Render fournit process.env.PORT)
const PORT = process.env.PORT || 10000;

// Démarre le serveur
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
