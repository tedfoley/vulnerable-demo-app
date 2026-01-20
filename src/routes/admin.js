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
// CWE-78: Using execFile with argument array prevents command injection
router.get('/ping', (req, res) => {
  const host = req.query.host;
  
  // Prevent type confusion: ensure host is a string, not an array
  if (typeof host !== 'string') {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // Validate input: only allow valid IP addresses or hostnames
  // Using simple character allowlist to avoid regex backtracking vulnerabilities
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$/;
  
  if (host.length > 255 || (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // Additional check: hostname segments must not start/end with hyphen
  if (!ipRegex.test(host)) {
    const segments = host.split('.');
    for (const segment of segments) {
      if (segment.startsWith('-') || segment.endsWith('-') || segment.length === 0 || segment.length > 63) {
        return res.status(400).json({ error: 'Invalid host format' });
      }
    }
  }
  
  // SECURE: Using execFile with arguments array prevents shell injection
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

// FIXED: Command Injection vulnerability #2
// CWE-78: Using execFile with argument array prevents command injection
router.post('/backup', authenticate, (req, res) => {
  const filename = req.body.filename;
  
  // Validate input: only allow alphanumeric characters, hyphens, and underscores
  const filenameRegex = /^[a-zA-Z0-9_-]+$/;
  
  if (!filename || !filenameRegex.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename format. Only alphanumeric characters, hyphens, and underscores are allowed.' });
  }
  
  // SECURE: Using execFile with arguments array prevents shell injection
  const outputPath = `/tmp/${filename}.tar.gz`;
  execFile('tar', ['-czf', outputPath, '/var/log'], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ success: true, message: `Backup created: ${filename}.tar.gz` });
    }
  });
});

// FIXED: Command Injection vulnerability #3
// CWE-78: Using execFile with argument array prevents command injection
router.get('/lookup', (req, res) => {
  const domain = req.query.domain;
  
  // Prevent type confusion: ensure domain is a string, not an array
  if (typeof domain !== 'string') {
    return res.status(400).json({ error: 'Invalid domain format' });
  }
  
  // Validate input: only allow valid domain names
  // Using simple character allowlist to avoid regex backtracking vulnerabilities
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$/;
  
  if (domain.length > 255 || !domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }
  
  // Additional check: domain segments must not start/end with hyphen
  const segments = domain.split('.');
  for (const segment of segments) {
    if (segment.startsWith('-') || segment.endsWith('-') || segment.length === 0 || segment.length > 63) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }
  }
  
  // SECURE: Using execFile with arguments array prevents shell injection
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

// FIXED: Command Injection vulnerability #4
// CWE-78: Using execFile with argument array prevents command injection
router.get('/safe-ping', (req, res) => {
  const host = req.query.host;
  
  // Prevent type confusion: ensure host is a string, not an array
  if (typeof host !== 'string') {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // Validate input: only allow valid IP addresses or hostnames
  // Using simple character allowlist to avoid regex backtracking vulnerabilities
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$/;
  
  if (host.length > 255 || (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // Additional check: hostname segments must not start/end with hyphen
  if (!ipRegex.test(host)) {
    const segments = host.split('.');
    for (const segment of segments) {
      if (segment.startsWith('-') || segment.endsWith('-') || segment.length === 0 || segment.length > 63) {
        return res.status(400).json({ error: 'Invalid host format' });
      }
    }
  }
  
  // SECURE: Using execFile with arguments array prevents shell injection
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

module.exports = router;
