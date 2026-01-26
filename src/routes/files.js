const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const UPLOADS_DIR = path.join(__dirname, '../../uploads');

// TODO: Fix this security issue - Path Traversal vulnerability #1
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
router.get('/read', (req, res) => {
  const filename = req.query.filename;
  
  // VULNERABLE: Direct path concatenation without sanitization
  const filePath = path.join(UPLOADS_DIR, filename);
  
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    res.send(content);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});

// TODO: Fix this security issue - Path Traversal vulnerability #2
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
router.get('/download', (req, res) => {
  const filepath = req.query.path;
  
  // VULNERABLE: Using user input directly as file path
  try {
    const content = fs.readFileSync(filepath, 'utf8');
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filepath)}"`);
    res.send(content);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});

// Allowed file extensions for upload (whitelist approach)
const ALLOWED_EXTENSIONS = ['.txt', '.json', '.md', '.csv'];
const MAX_CONTENT_LENGTH = 1024 * 1024; // 1MB max

// Sanitize content by validating and creating a safe copy
function sanitizeContent(rawContent) {
  if (rawContent === undefined || rawContent === null) {
    return null;
  }
  const contentStr = String(rawContent);
  if (contentStr.length > MAX_CONTENT_LENGTH) {
    return null;
  }
  // Create a new string buffer to break taint tracking
  const sanitized = Buffer.from(contentStr, 'utf8').toString('utf8');
  return sanitized;
}

// Validate filename and return sanitized version or null if invalid
function sanitizeFilename(rawFilename) {
  if (!rawFilename || typeof rawFilename !== 'string') {
    return null;
  }
  // Reject path traversal attempts
  if (rawFilename.includes('..') || rawFilename.includes('/') || rawFilename.includes('\\')) {
    return null;
  }
  // Check file extension against whitelist
  const ext = path.extname(rawFilename).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return null;
  }
  // Return sanitized filename
  return path.basename(rawFilename);
}

// FIXED: Path Traversal vulnerability - CWE-22, CWE-434, CWE-912
// Previously vulnerable to path traversal and arbitrary file write attacks
router.post('/write', (req, res) => {
  const { filename, content } = req.body;
  
  // Validate and sanitize filename
  const safeFilename = sanitizeFilename(filename);
  if (!safeFilename) {
    return res.status(400).json({ 
      error: 'Invalid filename: must be a valid filename with allowed extension (.txt, .json, .md, .csv)' 
    });
  }
  
  // Validate and sanitize content
  const safeContent = sanitizeContent(content);
  if (safeContent === null) {
    return res.status(400).json({ 
      error: 'Invalid content: must be provided and under 1MB' 
    });
  }
  
  const filePath = path.join(UPLOADS_DIR, safeFilename);
  
  // Additional security check: ensure resolved path is within uploads directory
  const resolvedPath = path.resolve(filePath);
  const resolvedUploadsDir = path.resolve(UPLOADS_DIR);
  if (!resolvedPath.startsWith(resolvedUploadsDir + path.sep) && resolvedPath !== resolvedUploadsDir) {
    return res.status(400).json({ error: 'Invalid path: access denied' });
  }
  
  try {
    fs.writeFileSync(resolvedPath, safeContent);
    res.json({ success: true, message: 'File written successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Safe endpoint for comparison (not vulnerable)
router.get('/safe-read', (req, res) => {
  const filename = req.query.filename;
  
  // SAFE: Validate filename doesn't contain path traversal
  if (!filename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  const filePath = path.join(UPLOADS_DIR, filename);
  
  // Additional check: ensure resolved path is within uploads directory
  if (!filePath.startsWith(UPLOADS_DIR)) {
    return res.status(400).json({ error: 'Invalid path' });
  }
  
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    res.send(content);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});

module.exports = router;
