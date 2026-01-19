const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');

// Helper function to validate hostname/domain without ReDoS-vulnerable regex
// Uses simple character validation + structural checks
function isValidHostname(hostname) {
  if (!hostname || hostname.length > 253) return false;
  
  // Only allow alphanumeric, hyphens, and dots
  if (!/^[a-zA-Z0-9.-]+$/.test(hostname)) return false;
  
  // Cannot start or end with hyphen or dot
  if (/^[-.]|[-.]$/.test(hostname)) return false;
  
  // Cannot have consecutive dots
  if (/\.\./.test(hostname)) return false;
  
  // Each label must be 1-63 characters
  const labels = hostname.split('.');
  return labels.every(label => label.length >= 1 && label.length <= 63 && !/^-|-$/.test(label));
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

// FIXED: Command Injection vulnerability #1
// CWE-78: Using execFile with arguments array prevents shell injection
router.get('/ping', (req, res) => {
  const host = req.query.host;
  
  // Validate input format (IP address or hostname)
  // Using simple regex for IP to avoid ReDoS, and helper function for hostname
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  
  if (!host || (!ipRegex.test(host) && !isValidHostname(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // SECURE: Using execFile with arguments array - no shell interpretation
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
  
  // Validate filename - only allow alphanumeric, hyphens, and underscores
  const filenameRegex = /^[a-zA-Z0-9_-]+$/;
  
  if (!filename || !filenameRegex.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename format. Only alphanumeric characters, hyphens, and underscores are allowed.' });
  }
  
  // SECURE: Using execFile with arguments array - no shell interpretation
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
// CWE-78: Using execFile with arguments array prevents shell injection
router.get('/lookup', (req, res) => {
  const domain = req.query.domain;
  
  // Validate domain format using helper function to avoid ReDoS
  if (!isValidHostname(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }
  
  // SECURE: Using execFile with arguments array - no shell interpretation
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
// CWE-78: Using execFile with arguments array prevents shell injection
router.get('/safe-ping', (req, res) => {
  const host = req.query.host;
  
  // Validate input format (IP address or hostname)
  // Using simple regex for IP to avoid ReDoS, and helper function for hostname
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  
  if (!host || (!ipRegex.test(host) && !isValidHostname(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  // SECURE: Using execFile with arguments array - no shell interpretation
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

module.exports = router;
