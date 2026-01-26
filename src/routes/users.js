const express = require('express');
const router = express.Router();
const Database = require('better-sqlite3');

const db = new Database(':memory:');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL
  )
`);

db.exec(`
  INSERT INTO users (username, email, password) VALUES 
  ('admin', 'admin@example.com', 'admin123'),
  ('john', 'john@example.com', 'password123'),
  ('jane', 'jane@example.com', 'secret456')
`);

// FIXED: SQL Injection vulnerability #1 - Now using parameterized query
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
router.get('/search', (req, res) => {
  const username = req.query.username;
  
  // SAFE: Using parameterized query to prevent SQL injection
  const query = "SELECT id, username, email FROM users WHERE username = ?";
  
  try {
    const users = db.prepare(query).all(username);
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// FIXED: SQL Injection vulnerability #2 - Now using parameterized query
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
router.get('/find', (req, res) => {
  const email = req.query.email;
  
  // SAFE: Using parameterized query to prevent SQL injection
  const query = "SELECT id, username, email FROM users WHERE email = ?";
  
  try {
    const users = db.prepare(query).all(email);
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// FIXED: SQL Injection vulnerability #3 - Now using parameterized query
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // SAFE: Using parameterized query to prevent SQL injection
  const query = "SELECT * FROM users WHERE username = ? AND password = ?";
  
  try {
    const user = db.prepare(query).get(username, password);
    if (user) {
      res.json({ success: true, message: 'Login successful', userId: user.id });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Safe endpoint for comparison (not vulnerable)
router.get('/safe-search', (req, res) => {
  const username = req.query.username;
  
  // SAFE: Using parameterized query
  const query = "SELECT id, username, email FROM users WHERE username = ?";
  
  try {
    const users = db.prepare(query).all(username);
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
