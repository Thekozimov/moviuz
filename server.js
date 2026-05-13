const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'moviuz_secret_key_2025';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Upload papkalarini yaratish
const uploadDir = path.join(__dirname, 'uploads');
const postersDir = path.join(uploadDir, 'posters');
const bannersDir = path.join(uploadDir, 'banners');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
if (!fs.existsSync(postersDir)) fs.mkdirSync(postersDir);
if (!fs.existsSync(bannersDir)) fs.mkdirSync(bannersDir);

// Multer konfiguratsiyasi
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'poster') cb(null, postersDir);
        else if (file.fieldname === 'banner') cb(null, bannersDir);
        else cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, unique + path.extname(file.originalname));
    }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// SQLite database
const db = new sqlite3.Database('./database.sqlite');

// Tables yaratish
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Dramas table
    db.run(`CREATE TABLE IF NOT EXISTS dramas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        titleKr TEXT,
        genre TEXT NOT NULL,
        year INTEGER NOT NULL,
        rating REAL DEFAULT 0,
        badge TEXT,
        emoji TEXT DEFAULT '🎬',
        description TEXT,
        status TEXT DEFAULT 'active',
        poster TEXT,
        banner TEXT,
        views INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Episodes table
    db.run(`CREATE TABLE IF NOT EXISTS episodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        drama_id INTEGER NOT NULL,
        episode_num INTEGER NOT NULL,
        title TEXT,
        duration INTEGER DEFAULT 60,
        video_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(drama_id) REFERENCES dramas(id) ON DELETE CASCADE
    )`);

    // Admin maxsus (sozlamalar)
    db.run(`CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    // Default admin qo'shish (agar mavjud bo'lmasa)
    const adminEmail = 'olmasbekhamroyev673@gmail.com';
    const adminPass = 'khamrayev26';
    bcrypt.hash(adminPass, 10, (err, hash) => {
        if (!err) {
            db.run(`INSERT OR IGNORE INTO admins (email, password) VALUES (?, ?)`, [adminEmail, hash]);
        }
    });
});

// ============= AUTH MIDDLEWARE =============
function verifyUserToken(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token kerak' });
    }
    const token = auth.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Yaroqsiz token' });
    }
}

function verifyAdminToken(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Admin token kerak' });
    }
    const token = auth.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin huquqi kerak' });
        }
        req.admin = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Yaroqsiz token' });
    }
}

// ============= USER ROUTES =============
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Barcha maydonlarni to\'ldiring' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Parol kamida 6 belgi' });
    }

    try {
        const hash = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (name, email, password) VALUES (?, ?, ?)`, [name, email, hash], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ error: 'Bu email allaqachon ro\'yxatdan o\'tgan' });
                }
                return res.status(500).json({ error: 'Server xatosi' });
            }
            const token = jwt.sign({ id: this.lastID, email, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
            res.json({ token, name, id: this.lastID });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server xatosi' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email va parolni kiriting' });
    }

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Email yoki parol noto\'g\'ri' });
        }
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ error: 'Email yoki parol noto\'g\'ri' });
        }
        const token = jwt.sign({ id: user.id, email: user.email, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, name: user.name, id: user.id });
    });
});

// ============= ADMIN ROUTES =============
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email va parolni kiriting' });
    }

    db.get(`SELECT * FROM admins WHERE email = ?`, [email], async (err, admin) => {
        if (err || !admin) {
            return res.status(401).json({ error: 'Admin topilmadi' });
        }
        const valid = await bcrypt.compare(password, admin.password);
        if (!valid) {
            return res.status(401).json({ error: 'Parol noto\'g\'ri' });
        }
        const token = jwt.sign({ id: admin.id, email: admin.email, role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token });
    });
});

app.get('/api/admin/verify', verifyAdminToken, (req, res) => {
    res.json({ valid: true });
});

app.get('/api/admin/stats', verifyAdminToken, (req, res) => {
    db.get(`SELECT COUNT(*) as totalDramas FROM dramas WHERE status = 'active'`, (err, active) => {
        db.get(`SELECT COUNT(*) as totalDramasAll FROM dramas`, (err2, all) => {
            db.get(`SELECT COUNT(*) as totalUsers FROM users`, (err3, users) => {
                db.all(`SELECT SUM(views) as totalViews FROM dramas`, (err4, views) => {
                    db.all(`SELECT title, views, rating FROM dramas ORDER BY views DESC LIMIT 5`, (err5, top) => {
                        res.json({
                            totalDramas: all?.totalDramasAll || 0,
                            activeDramas: active?.totalDramas || 0,
                            totalUsers: users?.totalUsers || 0,
                            totalViews: views?.[0]?.totalViews || 0,
                            topDramas: top || []
                        });
                    });
                });
            });
        });
    });
});

app.get('/api/admin/dramas', verifyAdminToken, (req, res) => {
    db.all(`SELECT * FROM dramas ORDER BY created_at DESC`, (err, dramas) => {
        if (err) return res.status(500).json({ error: err.message });
        let pending = dramas.length;
        if (pending === 0) return res.json([]);
        
        dramas.forEach((drama, idx) => {
            db.all(`SELECT * FROM episodes WHERE drama_id = ? ORDER BY episode_num`, [drama.id], (err, eps) => {
                drama.episodes = eps || [];
                drama._epCount = eps?.length || 0;
                pending--;
                if (pending === 0) res.json(dramas);
            });
        });
    });
});

app.get('/api/admin/users', verifyAdminToken, (req, res) => {
    db.all(`SELECT id, name, email, created_at FROM users ORDER BY created_at DESC`, (err, users) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(users);
    });
});

app.post('/api/admin/dramas', verifyAdminToken, upload.fields([{ name: 'poster' }, { name: 'banner' }]), (req, res) => {
    const { title, titleKr, genre, year, rating, badge, emoji, description, status, episodeCount } = req.body;
    if (!title || !genre || !year) {
        return res.status(400).json({ error: 'Title, janr va yil majburiy' });
    }

    const posterPath = req.files?.poster ? `/uploads/posters/${req.files.poster[0].filename}` : null;
    const bannerPath = req.files?.banner ? `/uploads/banners/${req.files.banner[0].filename}` : null;

    db.run(`INSERT INTO dramas (title, titleKr, genre, year, rating, badge, emoji, description, status, poster, banner)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [title, titleKr || '', genre, year, rating || 0, badge || '', emoji || '🎬', description || '', status || 'active', posterPath, bannerPath],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            const dramaId = this.lastID;
            const epCount = parseInt(episodeCount) || 0;
            let inserted = 0;
            
            for (let i = 1; i <= epCount; i++) {
                const epTitle = req.body[`ep_title_${i}`] || `${i}-qism`;
                const epUrl = req.body[`ep_url_${i}`] || '';
                const epDur = req.body[`ep_dur_${i}`] || 60;
                db.run(`INSERT INTO episodes (drama_id, episode_num, title, duration, video_url) VALUES (?, ?, ?, ?, ?)`,
                    [dramaId, i, epTitle, epDur, epUrl], (err2) => {
                        if (err2) console.error(err2);
                        inserted++;
                        if (inserted === epCount || (epCount === 0 && inserted === 0)) {
                            res.json({ id: dramaId, message: 'Drama yaratildi' });
                        }
                    });
            }
            if (epCount === 0) res.json({ id: dramaId, message: 'Drama yaratildi' });
        });
});

app.delete('/api/admin/dramas/:id', verifyAdminToken, (req, res) => {
    const id = req.params.id;
    db.run(`DELETE FROM episodes WHERE drama_id = ?`, [id]);
    db.run(`DELETE FROM dramas WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ deleted: true });
    });
});

app.put('/api/admin/dramas/:id', verifyAdminToken, (req, res) => {
    const { status } = req.body;
    const id = req.params.id;
    db.run(`UPDATE dramas SET status = ? WHERE id = ?`, [status, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ updated: true });
    });
});

// ============= PUBLIC ROUTES =============
app.get('/api/dramas', (req, res) => {
    let { genre, search } = req.query;
    let sql = `SELECT * FROM dramas WHERE status = 'active'`;
    let params = [];
    
    if (genre && genre !== 'all') {
        sql += ` AND genre = ?`;
        params.push(genre);
    }
    if (search) {
        sql += ` AND title LIKE ?`;
        params.push(`%${search}%`);
    }
    sql += ` ORDER BY created_at DESC`;
    
    db.all(sql, params, (err, dramas) => {
        if (err) return res.status(500).json({ error: err.message });
        let pending = dramas.length;
        if (pending === 0) return res.json([]);
        
        dramas.forEach((drama, idx) => {
            db.all(`SELECT * FROM episodes WHERE drama_id = ? ORDER BY episode_num`, [drama.id], (err, eps) => {
                drama.episodes = eps || [];
                drama._epCount = eps?.length || 0;
                pending--;
                if (pending === 0) res.json(dramas);
            });
        });
    });
});

app.get('/api/dramas/:id', (req, res) => {
    const id = req.params.id;
    db.get(`SELECT * FROM dramas WHERE id = ?`, [id], (err, drama) => {
        if (err || !drama) return res.status(404).json({ error: 'Drama topilmadi' });
        
        // Ko'rishlar sonini oshirish
        db.run(`UPDATE dramas SET views = views + 1 WHERE id = ?`, [id]);
        
        db.all(`SELECT * FROM episodes WHERE drama_id = ? ORDER BY episode_num`, [id], (err, episodes) => {
            drama.episodes = episodes || [];
            res.json(drama);
        });
    });
});

// ============= FRONTEND =============
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📧 Admin email: olmasbekhamroyev673@gmail.com`);
    console.log(`🔑 Admin parol: khamrayev26`);
});