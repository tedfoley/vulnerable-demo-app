const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');

// ReDoS-safe validation helper functions
// Uses simple character class checks and programmatic validation instead of complex regex
function isValidIPv4(str) {
  const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = str.match(ipRegex);
  if (!match) return false;
  return match.slice(1).every(octet => parseInt(octet, 10) <= 255);
}

function isValidHostname(str) {
  if (!str || str.length > 253) return false;
  // Only allow alphanumeric, hyphens, and dots
  if (!/^[a-zA-Z0-9.-]+$/.test(str)) return false;
  // Cannot start or end with hyphen or dot
  if (/^[-.]|[-.]$/.test(str)) return false;
  // Cannot have consecutive dots
  if (/\.\./.test(str)) return false;
  // Each label must be valid
  const labels = str.split('.');
  return labels.every(label => {
    if (label.length === 0 || label.length > 63) return false;
    if (/^-|-$/.test(label)) return false;
    return true;
  });
}

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
  
  // Validate input using ReDoS-safe helper functions
  if (!host || (!isValidIPv4(host) && !isValidHostname(host))) {
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
  
  // Validate input using ReDoS-safe helper function
  if (!domain || !isValidHostname(domain)) {
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
  
  // Validate input using ReDoS-safe helper functions
  if (!host || (!isValidIPv4(host) && !isValidHostname(host))) {
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
