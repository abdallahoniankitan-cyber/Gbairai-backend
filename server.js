// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);

const app = express();
app.use(helmet());
app.use(express.json());

// Config
const FRONT_ORIGIN = process.env.FRONT_ORIGIN || 'https://gbairai.netlify.app';
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL || null;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-this';

// Trust proxy if behind a proxy (Render, Heroku, etc.) so secure cookies work
if (NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// CORS
app.use(cors({
  origin: FRONT_ORIGIN,
  credentials: true
}));

// DB pool (optional in dev, required in prod)
let pool = null;
if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
} else if (NODE_ENV === 'production') {
  console.error('DATABASE_URL is required in production.');
  process.exit(1);
}

// Session store: prefer Postgres-backed store when pool exists, else MemoryStore in dev
const sessionMiddleware = session({
  store: pool ? new PgSession({
    pool: pool,
    tableName: 'session'
  }) : undefined,
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: NODE_ENV === 'production',            // produit: true (HTTPS)
    httpOnly: true,
    sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 jours
  }
});
app.use(sessionMiddleware);

// In-memory fallback (dev only)
let inMemory = {
  users: [],      // { username, passwordHash }
  posts: [],      // { id, user, content, zone, likes, dislikes, likedBy, dislikedBy, comments, created_at }
  zones: [],
  nextPostId: 1
};

// Ensure tables for Postgres
async function ensureTables() {
  if (!pool) return;
  // Create users, zones, posts, and session table is created by connect-pg-simple automatically.
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
      liked_by JSONB DEFAULT '[]'::jsonb,
      disliked_by JSONB DEFAULT '[]'::jsonb,
      comments JSONB DEFAULT '[]'::jsonb,
      created_at TIMESTAMP DEFAULT now()
    );
  `);
  // Indexes for performance
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_posts_zone ON posts(zone);`);
}

(async () => {
  try {
    await ensureTables();
    console.log('DB ready (if configured).');
  } catch(err) {
    console.warn('DB setup error (non-fatal in dev):', err.message);
  }
})();

// Helpers
function sendServerError(res, e) {
  console.error(e);
  return res.status(500).json({ error: 'server_error', message: e.message || String(e) });
}

function safeParseJsonField(field) {
  // Accept already-parsed arrays or JSON strings
  if (!field) return [];
  if (Array.isArray(field)) return field;
  try {
    return JSON.parse(field);
  } catch (e) {
    return [];
  }
}
function rowToPost(row) {
  return {
    id: row.id,
    user: row.username,
    content: row.content,
    zone: row.zone,
    likes: +row.likes || 0,
    dislikes: +row.dislikes || 0,
    likedBy: safeParseJsonField(row.liked_by),
    dislikedBy: safeParseJsonField(row.disliked_by),
    comments: safeParseJsonField(row.comments),
    created_at: row.created_at
  };
}

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.username) return next();
  return res.status(401).json({ error: 'not_logged_in' });
}

// --- AUTH: register/login combined (same behavior as before) ---
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'username & password required' });

    // DEV in-memory
    if (!pool) {
      let user = inMemory.users.find(u => u.username === username);
      if (!user) {
        const hash = bcrypt.hashSync(password, 10);
        user = { username, passwordHash: hash };
        inMemory.users.push(user);
      } else {
        if (!bcrypt.compareSync(password, user.passwordHash)) {
          return res.status(401).json({ success: false, message: 'invalid credentials' });
        }
      }
      req.session.username = username;
      return res.json({ success: true, user: { username } });
    }

    // With Postgres
    const r = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (r.rowCount === 0) {
      const hash = bcrypt.hashSync(password, 10);
      await pool.query('INSERT INTO users (username, password) VALUES ($1,$2)', [username, hash]);
      req.session.username = username;
      return res.json({ success: true, user: { username } });
    } else {
      const user = r.rows[0];
      if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'invalid credentials' });
      req.session.username = username;
      return res.json({ success: true, user: { username } });
    }
  } catch (e) {
    return sendServerError(res, e);
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'logout_failed' });
    res.clearCookie('connect.sid', { path: '/' });
    return res.json({ success: true });
  });
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.username) return res.json({ username: req.session.username });
  return res.status(401).json({ error: 'not_logged_in' });
});

// ZONES
app.get('/api/zones', async (req, res) => {
  try {
    if (!pool) return res.json(inMemory.zones.slice().sort());
    const r = await pool.query('SELECT name FROM zones ORDER BY name');
    return res.json(r.rows.map(r => r.name));
  } catch (e) { return sendServerError(res, e); }
});

app.post('/api/zones', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'missing_name' });
    if (!pool) {
      if (!inMemory.zones.includes(name)) inMemory.zones.push(name);
      return res.json({ name });
    }
    const r = await pool.query('INSERT INTO zones (name) VALUES ($1) ON CONFLICT (name) DO NOTHING RETURNING name', [name]);
    if (r.rowCount === 0) return res.status(409).json({ error: 'already_exists', name });
    return res.json({ name: r.rows[0].name });
  } catch (e) { return sendServerError(res, e); }
});

// POSTS - with pagination support (optional)
app.get('/api/posts', async (req, res) => {
  try {
    // Optional query params: page, limit, zone
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '50', 10)));
    const offset = (page - 1) * limit;
    const zoneFilter = req.query.zone;

    if (!pool) {
      let posts = inMemory.posts.slice().reverse();
      if (zoneFilter) posts = posts.filter(p => p.zone === zoneFilter);
      const paginated = posts.slice(offset, offset + limit);
      return res.json(paginated);
    }

    if (zoneFilter) {
      const r = await pool.query('SELECT * FROM posts WHERE zone=$1 ORDER BY id DESC LIMIT $2 OFFSET $3', [zoneFilter, limit, offset]);
      return res.json(r.rows.map(rowToPost));
    } else {
      const r = await pool.query('SELECT * FROM posts ORDER BY id DESC LIMIT $1 OFFSET $2', [limit, offset]);
      return res.json(r.rows.map(rowToPost));
    }
  } catch (e) { return sendServerError(res, e); }
});

// Create post
app.post('/api/posts', requireAuth, async (req, res) => {
  try {
    const username = req.session.username;
    const { content, zone } = req.body;
    if (!content || !content.trim()) return res.status(400).json({ error: 'empty_content' });

    // If zone provided, ensure it exists (if using DB)
    if (zone) {
      if (pool) {
        const zr = await pool.query('SELECT 1 FROM zones WHERE name=$1', [zone]);
        if (zr.rowCount === 0) return res.status(400).json({ error: 'invalid_zone' });
      } else {
        if (!inMemory.zones.includes(zone)) return res.status(400).json({ error: 'invalid_zone' });
      }
    }

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
       VALUES ($1,$2,$3,0,0,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb) RETURNING *`,
      [username, content, zone || null]
    );
    return res.json(rowToPost(r.rows[0]));
  } catch (e) { return sendServerError(res, e); }
});

// Update post (owner only)
app.put('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    const id = +req.params.id;
    const username = req.session.username;
    const { content } = req.body;
    if (!content || !content.trim()) return res.status(400).json({ error: 'missing_content' });

    if (!pool) {
      const p = inMemory.posts.find(x => x.id === id);
      if (!p) return res.status(404).json({ error: 'not_found' });
      if (p.user !== username) return res.status(403).json({ error: 'forbidden' });
      p.content = content;
      return res.json(p);
    }

    const cur = await pool.query('SELECT * FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error: 'not_found' });
    if (cur.rows[0].username !== username) return res.status(403).json({ error: 'forbidden' });

    const updated = await pool.query('UPDATE posts SET content=$1 WHERE id=$2 RETURNING *', [content, id]);
    return res.json(rowToPost(updated.rows[0]));
  } catch (e) { return sendServerError(res, e); }
});

// Delete post (owner only)
app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    const id = +req.params.id;
    const username = req.session.username;

    if (!pool) {
      const idx = inMemory.posts.findIndex(x => x.id === id);
      if (idx === -1) return res.status(404).json({ error: 'not_found' });
      if (inMemory.posts[idx].user !== username) return res.status(403).json({ error: 'forbidden' });
      inMemory.posts.splice(idx, 1);
      return res.json({ success: true });
    }

    const cur = await pool.query('SELECT username FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error: 'not_found' });
    if (cur.rows[0].username !== username) return res.status(403).json({ error: 'forbidden' });

    await pool.query('DELETE FROM posts WHERE id=$1', [id]);
    return res.json({ success: true });
  } catch (e) { return sendServerError(res, e); }
});

// COMMENTS
app.post('/api/posts/:id/comments', requireAuth, async (req, res) => {
  try {
    const id = +req.params.id;
    const username = req.session.username;
    const text = (req.body.text || '').trim();
    if (!text) return res.status(400).json({ error: 'empty_comment' });

    if (!pool) {
      const post = inMemory.posts.find(x => x.id === id);
      if (!post) return res.status(404).json({ error: 'not_found' });
      post.comments = post.comments || [];
      post.comments.push({ user: username, text, created_at: new Date().toISOString() });
      return res.json(post);
    }

    const cur = await pool.query('SELECT comments FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error: 'not_found' });
    const comments = safeParseJsonField(cur.rows[0].comments);
    comments.push({ user: username, text, created_at: new Date().toISOString() });
    const updated = await pool.query('UPDATE posts SET comments=$1 WHERE id=$2 RETURNING *', [JSON.stringify(comments), id]);
    return res.json(rowToPost(updated.rows[0]));
  } catch (e) { return sendServerError(res, e); }
});

// Delete comment by index (owner of comment)
app.delete('/api/posts/:id/comments/:idx', requireAuth, async (req, res) => {
  try {
    const id = +req.params.id;
    const idx = +req.params.idx;
    const username = req.session.username;

    if (!Number.isInteger(idx) || idx < 0) return res.status(400).json({ error: 'invalid_index' });

    if (!pool) {
      const post = inMemory.posts.find(x => x.id === id);
      if (!post) return res.status(404).json({ error: 'not_found' });
      if (!post.comments || !post.comments[idx]) return res.status(404).json({ error: 'not_found' });
      if (post.comments[idx].user !== username) return res.status(403).json({ error: 'forbidden' });
      post.comments.splice(idx, 1);
      return res.json(post);
    }

    const cur = await pool.query('SELECT comments FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error: 'not_found' });
    const comments = safeParseJsonField(cur.rows[0].comments);
    if (!comments[idx]) return res.status(404).json({ error: 'not_found' });
    if (comments[idx].user !== username) return res.status(403).json({ error: 'forbidden' });
    comments.splice(idx, 1);
    const updated = await pool.query('UPDATE posts SET comments=$1 WHERE id=$2 RETURNING *', [JSON.stringify(comments), id]);
    return res.json(rowToPost(updated.rows[0]));
  } catch (e) { return sendServerError(res, e); }
});

// LIKE
app.post('/api/posts/:id/like', requireAuth, async (req, res) => {
  try {
    const id = +req.params.id;
    const username = req.session.username;

    if (!pool) {
      const post = inMemory.posts.find(x => x.id === id);
      if (!post) return res.status(404).json({ error: 'not_found' });
      post.likedBy = post.likedBy || [];
      post.dislikedBy = post.dislikedBy || [];
      if (post.likedBy.includes(username)) {
        // remove like
        post.likedBy = post.likedBy.filter(u => u !== username);
        post.likes = Math.max(0, (post.likes || 0) - 1);
      } else {
        // add like, remove possible dislike
        post.likedBy.push(username);
        post.likes = (post.likes || 0) + 1;
        if (post.dislikedBy.includes(username)) {
          post.dislikedBy = post.dislikedBy.filter(u => u !== username);
          post.dislikes = Math.max(0, (post.dislikes || 0) - 1);
        }
      }
      return res.json(post);
    }

    const cur = await pool.query('SELECT liked_by, disliked_by, likes, dislikes FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error: 'not_found' });

    let liked = safeParseJsonField(cur.rows[0].liked_by);
    let disliked = safeParseJsonField(cur.rows[0].disliked_by);
    let likes = +cur.rows[0].likes || 0;
    let dislikes = +cur.rows[0].dislikes || 0;

    if (liked.includes(username)) {
      liked = liked.filter(u => u !== username);
      likes = Math.max(0, likes - 1);
    } else {
      liked.push(username);
      likes = likes + 1;
      if (disliked.includes(username)) {
        disliked = disliked.filter(u => u !== username);
        dislikes = Math.max(0, dislikes - 1);
      }
    }

    const updated = await pool.query(
      'UPDATE posts SET liked_by=$1, disliked_by=$2, likes=$3, dislikes=$4 WHERE id=$5 RETURNING *',
      [JSON.stringify(liked), JSON.stringify(disliked), likes, dislikes, id]
    );
    return res.json(rowToPost(updated.rows[0]));
  } catch (e) { return sendServerError(res, e); }
});

// DISLIKE
app.post('/api/posts/:id/dislike', requireAuth, async (req, res) => {
  try {
    const id = +req.params.id;
    const username = req.session.username;

    if (!pool) {
      const post = inMemory.posts.find(x => x.id === id);
      if (!post) return res.status(404).json({ error: 'not_found' });
      post.likedBy = post.likedBy || [];
      post.dislikedBy = post.dislikedBy || [];
      if (post.dislikedBy.includes(username)) {
        post.dislikedBy = post.dislikedBy.filter(u => u !== username);
        post.dislikes = Math.max(0, (post.dislikes || 0) - 1);
      } else {
        post.dislikedBy.push(username);
        post.dislikes = (post.dislikes || 0) + 1;
        if (post.likedBy.includes(username)) {
          post.likedBy = post.likedBy.filter(u => u !== username);
          post.likes = Math.max(0, (post.likes || 0) - 1);
        }
      }
      return res.json(post);
    }

    const cur = await pool.query('SELECT liked_by, disliked_by, likes, dislikes FROM posts WHERE id=$1', [id]);
    if (cur.rowCount === 0) return res.status(404).json({ error: 'not_found' });

    let liked = safeParseJsonField(cur.rows[0].liked_by);
    let disliked = safeParseJsonField(cur.rows[0].disliked_by);
    let likes = +cur.rows[0].likes || 0;
    let dislikes = +cur.rows[0].dislikes || 0;

    if (disliked.includes(username)) {
      disliked = disliked.filter(u => u !== username);
      dislikes = Math.max(0, dislikes - 1);
    } else {
      disliked.push(username);
      dislikes = dislikes + 1;
      if (liked.includes(username)) {
        liked = liked.filter(u => u !== username);
        likes = Math.max(0, likes - 1);
      }
    }

    const updated = await pool.query(
      'UPDATE posts SET liked_by=$1, disliked_by=$2, likes=$3, dislikes=$4 WHERE id=$5 RETURNING *',
      [JSON.stringify(liked), JSON.stringify(disliked), likes, dislikes, id]
    );
    return res.json(rowToPost(updated.rows[0]));
  } catch (e) { return sendServerError(res, e); }
});

// Catch-all
app.use((req, res) => {
  res.status(404).json({ error: 'not_found', message: 'Cette route n\'existe pas ou n\'est pas une API.' });
});

// Start
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT} (NODE_ENV=${NODE_ENV})`);
});
