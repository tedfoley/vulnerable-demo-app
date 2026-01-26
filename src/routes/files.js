const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const UPLOADS_DIR = path.join(__dirname, '../../uploads');

// FIXED: Path Traversal vulnerability #1
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
router.get('/read', (req, res) => {
  const filename = req.query.filename;
  
  // Validate filename doesn't contain path traversal sequences
  if (!filename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  const filePath = path.join(UPLOADS_DIR, filename);
  const resolvedPath = path.resolve(filePath);
  
  // Ensure resolved path is within uploads directory
  if (!resolvedPath.startsWith(path.resolve(UPLOADS_DIR) + path.sep)) {
    return res.status(400).json({ error: 'Invalid path' });
  }
  
  try {
    const content = fs.readFileSync(resolvedPath, 'utf8');
    res.send(content);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});

// FIXED: Path Traversal vulnerability #2
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
router.get('/download', (req, res) => {
  const filename = req.query.path;
  
  // Validate filename doesn't contain path traversal sequences
  if (!filename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  const filePath = path.join(UPLOADS_DIR, filename);
  const resolvedPath = path.resolve(filePath);
  
  // Ensure resolved path is within uploads directory
  if (!resolvedPath.startsWith(path.resolve(UPLOADS_DIR) + path.sep)) {
    return res.status(400).json({ error: 'Invalid path' });
  }
  
  try {
    const content = fs.readFileSync(resolvedPath, 'utf8');
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(resolvedPath)}"`);
    res.send(content);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});

// FIXED: Path Traversal vulnerability #3
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
router.post('/write', (req, res) => {
  const { filename, content } = req.body;
  
  // Validate filename doesn't contain path traversal sequences
  if (!filename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  const filePath = path.join(UPLOADS_DIR, filename);
  const resolvedPath = path.resolve(filePath);
  
  // Ensure resolved path is within uploads directory
  if (!resolvedPath.startsWith(path.resolve(UPLOADS_DIR) + path.sep)) {
    return res.status(400).json({ error: 'Invalid path' });
  }
  
  try {
    fs.writeFileSync(resolvedPath, content);
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
