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

// FIXED: Command Injection vulnerability #1
// CWE-78: Using execFile with argument array prevents shell injection
router.get('/ping', (req, res) => {
  // Extract host as string, handling array case (prevent type confusion)
  const rawHost = req.query.host;
  const host = typeof rawHost === 'string' ? rawHost : (Array.isArray(rawHost) ? String(rawHost[0]) : '');
  
  if (!host) {
    return res.status(400).json({ error: 'Invalid host parameter' });
  }
  
  // Validate input format before execution (using simple regex to avoid ReDoS)
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/;
  
  if (host.length > 253 || host.includes('..') || 
      (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // SECURE: Using execFile with arguments array prevents command injection
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

// FIXED: Command Injection vulnerability #2
// CWE-78: Using execFile with argument array prevents shell injection
router.post('/backup', authenticate, (req, res) => {
  const filename = req.body.filename;
  
  // Validate filename to only allow safe characters (alphanumeric, underscore, hyphen)
  const filenameRegex = /^[a-zA-Z0-9_-]+$/;
  
  if (!filename || !filenameRegex.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename format. Only alphanumeric characters, underscores, and hyphens are allowed.' });
  }
  
  // SECURE: Using execFile with arguments array prevents command injection
  execFile('tar', ['-czf', `/tmp/${filename}.tar.gz`, '/var/log'], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ success: true, message: `Backup created: ${filename}.tar.gz` });
    }
  });
});

// FIXED: Command Injection vulnerability #3
// CWE-78: Using execFile with argument array prevents shell injection
router.get('/lookup', (req, res) => {
  // Extract domain as string, handling array case (prevent type confusion)
  const rawDomain = req.query.domain;
  const domain = typeof rawDomain === 'string' ? rawDomain : (Array.isArray(rawDomain) ? String(rawDomain[0]) : '');
  
  if (!domain) {
    return res.status(400).json({ error: 'Invalid domain parameter' });
  }
  
  // Validate domain format before execution (using simple regex to avoid ReDoS)
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/;
  
  if (domain.length > 253 || domain.includes('..') || !domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }
  
  // SECURE: Using execFile with arguments array prevents command injection
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

// FIXED: Safe endpoint now uses execFile for complete protection
router.get('/safe-ping', (req, res) => {
  // Extract host as string, handling array case (prevent type confusion)
  const rawHost = req.query.host;
  const host = typeof rawHost === 'string' ? rawHost : (Array.isArray(rawHost) ? String(rawHost[0]) : '');
  
  if (!host) {
    return res.status(400).json({ error: 'Invalid host parameter' });
  }
  
  // Validate input before using in command (using simple regex to avoid ReDoS)
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/;
  
  if (host.length > 253 || host.includes('..') ||
      (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // SECURE: Using execFile with arguments array prevents command injection
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

module.exports = router;
