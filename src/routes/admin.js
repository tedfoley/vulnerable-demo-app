const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');

// Helper function to safely extract string from request parameter (prevents type confusion)
// Express query/body params can be arrays if sent multiple times, e.g., ?host=a&host=b
function getStringParam(param) {
  if (typeof param === 'string') return param;
  if (Array.isArray(param) && param.length > 0 && typeof param[0] === 'string') return param[0];
  return null;
}

// Helper function to check if character is alphanumeric
function isAlphanumeric(char) {
  const code = char.charCodeAt(0);
  return (code >= 48 && code <= 57) ||  // 0-9
         (code >= 65 && code <= 90) ||  // A-Z
         (code >= 97 && code <= 122);   // a-z
}

// Helper function to validate a single hostname label (no regex to avoid ReDoS)
function isValidLabel(label) {
  if (label.length === 0 || label.length > 63) return false;
  // Must start and end with alphanumeric
  if (!isAlphanumeric(label[0])) return false;
  if (label.length > 1 && !isAlphanumeric(label[label.length - 1])) return false;
  // Middle characters can be alphanumeric or hyphen
  for (let i = 1; i < label.length - 1; i++) {
    const char = label[i];
    if (!isAlphanumeric(char) && char !== '-') return false;
  }
  return true;
}

// Helper function to validate hostname (no regex to avoid ReDoS)
function isValidHostname(hostname) {
  if (typeof hostname !== 'string' || hostname.length === 0 || hostname.length > 253) return false;
  const labels = hostname.split('.');
  return labels.every(isValidLabel);
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
// CWE-78: Using execFile with argument array prevents shell interpretation
router.get('/ping', (req, res) => {
  const host = getStringParam(req.query.host);
  
  // Validate input format (IP address or hostname)
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  
  if (!host || (!ipRegex.test(host) && !isValidHostname(host))) {
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
// CWE-78: Using execFile with argument array prevents shell interpretation
router.post('/backup', authenticate, (req, res) => {
  const filename = getStringParam(req.body.filename);
  
  // Validate filename (alphanumeric, hyphens, underscores only, no path traversal)
  const filenameRegex = /^[a-zA-Z0-9_-]+$/;
  
  if (!filename || !filenameRegex.test(filename) || filename.length > 100) {
    return res.status(400).json({ error: 'Invalid filename format' });
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
// CWE-78: Using execFile with argument array prevents shell interpretation
router.get('/lookup', (req, res) => {
  const domain = getStringParam(req.query.domain);
  
  // Validate domain format (hostname or IP address)
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  
  if (!domain || (!ipRegex.test(domain) && !isValidHostname(domain))) {
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

// FIXED: Command Injection vulnerability #4 (was labeled "safe" but still used exec)
// CWE-78: Using execFile with argument array prevents shell interpretation
router.get('/safe-ping', (req, res) => {
  const host = getStringParam(req.query.host);
  
  // Validate input before using in command
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  
  if (!host || (!ipRegex.test(host) && !isValidHostname(host))) {
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
