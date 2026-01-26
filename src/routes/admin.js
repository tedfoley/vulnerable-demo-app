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
// CWE-78: Using execFile with arguments array prevents shell injection
router.get('/ping', (req, res) => {
  const host = req.query.host;
  
  if (!host) {
    return res.status(400).json({ error: 'Host parameter is required' });
  }
  
  // Validate input format - using simple patterns to avoid ReDoS
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  // Simple hostname validation: alphanumeric, dots, and hyphens only
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$/;
  
  if (host.length > 253) {
    return res.status(400).json({ error: 'Host too long' });
  }
  
  if (!ipRegex.test(host) && !hostnameRegex.test(host)) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // SECURE: execFile does not spawn a shell, arguments passed as array
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

// FIXED: Command Injection vulnerability #2
// CWE-78: Using execFile with arguments array prevents shell injection
router.post('/backup', authenticate, (req, res) => {
  const filename = req.body.filename;
  
  if (!filename) {
    return res.status(400).json({ error: 'Filename parameter is required' });
  }
  
  // Validate filename - only allow alphanumeric, dash, underscore
  const filenameRegex = /^[a-zA-Z0-9_-]+$/;
  if (!filenameRegex.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename format. Only alphanumeric characters, dashes, and underscores allowed.' });
  }
  
  const outputPath = `/tmp/${filename}.tar.gz`;
  
  // SECURE: execFile does not spawn a shell, arguments passed as array
  execFile('tar', ['-czf', outputPath, '/var/log'], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ success: true, message: `Backup created: ${filename}.tar.gz` });
    }
  });
});

// FIXED: Command Injection vulnerability #3
// CWE-78: Using execFile with arguments array prevents shell injection
router.get('/lookup', (req, res) => {
  const domain = req.query.domain;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }
  
  // Validate domain format - using simple pattern to avoid ReDoS
  // Simple domain validation: alphanumeric, dots, and hyphens only
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$/;
  
  if (domain.length > 253) {
    return res.status(400).json({ error: 'Domain too long' });
  }
  
  if (!domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }
  
  // SECURE: execFile does not spawn a shell, arguments passed as array
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

// FIXED: Safe endpoint using execFile instead of exec
router.get('/safe-ping', (req, res) => {
  const host = req.query.host;
  
  if (!host) {
    return res.status(400).json({ error: 'Host parameter is required' });
  }
  
  // Validate input before using in command - using simple patterns to avoid ReDoS
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  // Simple hostname validation: alphanumeric, dots, and hyphens only
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$/;
  
  if (host.length > 253) {
    return res.status(400).json({ error: 'Host too long' });
  }
  
  if (!ipRegex.test(host) && !hostnameRegex.test(host)) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // SECURE: execFile does not spawn a shell, arguments passed as array
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

module.exports = router;
