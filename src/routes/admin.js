const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');

// Simple authentication middleware using environment variable
const authenticate = (req, res, next) => {
  const authHeader = req.headers['x-admin-auth'];
  const adminAuth = process.env.ADMIN_AUTH || 'admin';
  
  if (authHeader === adminAuth) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// FIXED: Command Injection vulnerability #1 (CWE-78)
// Using execFile with arguments array prevents shell injection
router.get('/ping', (req, res) => {
  const host = req.query.host;
  
  // Validate input: only allow valid IP addresses or hostnames
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$/;
  
  if (!host || (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // SECURE: Using execFile with arguments array - no shell spawned
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

// FIXED: Command Injection vulnerability #2 (CWE-78)
// Using execFile with arguments array prevents shell injection
router.post('/backup', authenticate, (req, res) => {
  const filename = req.body.filename;
  
  // Validate input: only allow alphanumeric characters, hyphens, and underscores
  const filenameRegex = /^[a-zA-Z0-9_-]+$/;
  
  if (!filename || !filenameRegex.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename format. Only alphanumeric characters, hyphens, and underscores are allowed.' });
  }
  
  // SECURE: Using execFile with arguments array - no shell spawned
  execFile('tar', ['-czf', `/tmp/${filename}.tar.gz`, '/var/log'], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ success: true, message: `Backup created: ${filename}.tar.gz` });
    }
  });
});

// FIXED: Command Injection vulnerability #3 (CWE-78)
// Using execFile with arguments array prevents shell injection
router.get('/lookup', (req, res) => {
  const domain = req.query.domain;
  
  // Validate input: only allow valid domain names
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$/;
  
  if (!domain || !domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }
  
  // SECURE: Using execFile with arguments array - no shell spawned
  execFile('nslookup', [domain], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ result: stdout });
    }
  });
});

// Endpoint that returns configuration
router.get('/config', authenticate, (req, res) => {
  res.json({
    token: process.env.SERVICE_TOKEN || 'demo',
    environment: process.env.NODE_ENV || 'development'
  });
});

// FIXED: Command Injection vulnerability #4 (CWE-78)
// Using execFile with arguments array prevents shell injection
router.get('/safe-ping', (req, res) => {
  const host = req.query.host;
  
  // Validate input: only allow valid IP addresses or hostnames
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$/;
  
  if (!host || (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // SECURE: Using execFile with arguments array - no shell spawned
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

module.exports = router;
