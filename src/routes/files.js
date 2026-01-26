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

// FIXED: Path Traversal vulnerability - CWE-22, CWE-434, CWE-912
// Previously vulnerable to path traversal and arbitrary file write attacks
router.post('/write', (req, res) => {
  const { filename, content } = req.body;
  
  // Validate filename to prevent path traversal attacks
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Filename is required' });
  }
  
  // Reject filenames containing path traversal sequences or directory separators
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename: path traversal not allowed' });
  }
  
  // Validate content exists and is a string
  if (content === undefined || content === null) {
    return res.status(400).json({ error: 'Content is required' });
  }
  
  const filePath = path.join(UPLOADS_DIR, filename);
  
  // Additional security check: ensure resolved path is within uploads directory
  const resolvedPath = path.resolve(filePath);
  const resolvedUploadsDir = path.resolve(UPLOADS_DIR);
  if (!resolvedPath.startsWith(resolvedUploadsDir + path.sep) && resolvedPath !== resolvedUploadsDir) {
    return res.status(400).json({ error: 'Invalid path: access denied' });
  }
  
  try {
    fs.writeFileSync(resolvedPath, String(content));
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
