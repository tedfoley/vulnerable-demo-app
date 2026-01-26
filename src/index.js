const express = require('express');
const path = require('path');

const usersRouter = require('./routes/users');
const filesRouter = require('./routes/files');
const adminRouter = require('./routes/admin');
const { safeRenderUserProfile, generateSessionToken } = require('./utils/helpers');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api/users', usersRouter);
app.use('/api/files', filesRouter);
app.use('/api/admin', adminRouter);

app.get('/', (req, res) => {
  res.send('<h1>Welcome to the Vulnerable Demo App</h1><p>This app is intentionally vulnerable for CodeQL testing.</p>');
});

app.get('/profile', (req, res) => {
  const username = req.query.username || 'Guest';
  const html = safeRenderUserProfile(username);
  res.send(html);
});

app.get('/session', (req, res) => {
  const token = generateSessionToken();
  res.json({ sessionToken: token });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
