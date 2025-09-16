const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../')));

const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database');
    }
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

    db.run(`CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    sku TEXT UNIQUE NOT NULL,
    quantity INTEGER NOT NULL,
    price REAL NOT NULL,
    category TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_modified DATETIME DEFAULT CURRENT_TIMESTAMP,
    modified_by TEXT NOT NULL,
    checksum TEXT NOT NULL
  )`);

    db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    message TEXT NOT NULL,
    user TEXT NOT NULL
  )`);
});

function generateChecksum(data) {
    let hash = 0;
    const dataString = JSON.stringify(data);
    if (dataString.length === 0) return hash;
    for (let i = 0; i < dataString.length; i++) {
        const char = dataString.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash |= 0; 
    }
    return hash.toString();
}

function authenticate(req, res, next) {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }


    req.user = token;
    next();
}


app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            if (row) {
                return res.status(400).json({ error: 'Username already exists' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to create user' });
                }

                db.run('INSERT INTO transactions (message, user) VALUES (?, ?)',
                    [`New user registered: ${username}`, 'system'], () => { });

                res.status(201).json({ message: 'User created successfully' });
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        db.run('INSERT INTO transactions (message, user) VALUES (?, ?)',
            ['User logged in', username], () => { });

        res.json({ message: 'Login successful', user: username });
    });
});

app.get('/api/inventory', authenticate, (req, res) => {
    db.all('SELECT * FROM inventory', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch inventory' });
        }
        res.json(rows);
    });
});

app.post('/api/inventory', authenticate, (req, res) => {
    const { id, name, sku, quantity, price, category } = req.body;
    const user = req.user;

    if (!name || !sku || quantity === undefined || price === undefined || !category) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const itemData = { name, sku, quantity, price, category };
    const checksum = generateChecksum(itemData);
    const now = new Date().toISOString();

    if (id) {
        db.run(
            `UPDATE inventory SET name = ?, sku = ?, quantity = ?, price = ?, category = ?, 
       last_modified = ?, modified_by = ?, checksum = ? WHERE id = ?`,
            [name, sku, quantity, price, category, now, user, checksum, id],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: 'SKU must be unique' });
                    }
                    return res.status(500).json({ error: 'Failed to update item' });
                }

                db.run('INSERT INTO transactions (message, user) VALUES (?, ?)',
                    [`Item updated: ${name} (SKU: ${sku})`, user], () => { });

                res.json({ message: 'Item updated successfully' });
            }
        );
    } else {
        db.run(
            `INSERT INTO inventory (name, sku, quantity, price, category, created_by, modified_by, checksum) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [name, sku, quantity, price, category, user, user, checksum],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: 'SKU must be unique' });
                    }
                    return res.status(500).json({ error: 'Failed to add item' });
                }

                db.run('INSERT INTO transactions (message, user) VALUES (?, ?)',
                    [`Item added: ${name} (SKU: ${sku})`, user], () => { });

                res.status(201).json({ message: 'Item added successfully', id: this.lastID });
            }
        );
    }
});

app.delete('/api/inventory/:id', authenticate, (req, res) => {
    const { id } = req.params;
    const user = req.user;

    db.get('SELECT name, sku FROM inventory WHERE id = ?', [id], (err, item) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!item) {
            return res.status(404).json({ error: 'Item not found' });
        }

        db.run('DELETE FROM inventory WHERE id = ?', [id], function (err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to delete item' });
            }

            db.run('INSERT INTO transactions (message, user) VALUES (?, ?)',
                [`Item deleted: ${item.name} (SKU: ${item.sku})`, user], () => { });

            res.json({ message: 'Item deleted successfully' });
        });
    });
});

app.get('/api/transactions', authenticate, (req, res) => {
    db.all('SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 100', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch transactions' });
        }
        res.json(rows);
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
