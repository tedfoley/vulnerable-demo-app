// Utility functions with intentional security vulnerabilities

// TODO: Fix this security issue - Cross-Site Scripting (XSS) vulnerability #1
// CWE-79: Improper Neutralization of Input During Web Page Generation
function renderUserProfile(username) {
  // VULNERABLE: Directly embedding user input in HTML without escaping
  return `
    <!DOCTYPE html>
    <html>
    <head><title>User Profile</title></head>
    <body>
      <h1>Welcome, ${username}!</h1>
      <p>This is your profile page.</p>
    </body>
    </html>
  `;
}

// TODO: Fix this security issue - Cross-Site Scripting (XSS) vulnerability #2
// CWE-79: Improper Neutralization of Input During Web Page Generation
function renderSearchResults(query, results) {
  // VULNERABLE: User input directly in HTML
  let html = `<h2>Search results for: ${query}</h2><ul>`;
  
  results.forEach(result => {
    html += `<li>${result}</li>`;
  });
  
  html += '</ul>';
  return html;
}

// TODO: Fix this security issue - Cross-Site Scripting (XSS) vulnerability #3
// CWE-79: Improper Neutralization of Input During Web Page Generation
function renderErrorPage(errorMessage) {
  // VULNERABLE: Error message directly embedded in HTML
  return `
    <!DOCTYPE html>
    <html>
    <head><title>Error</title></head>
    <body>
      <h1>An error occurred</h1>
      <p class="error">${errorMessage}</p>
      <a href="/">Go back to home</a>
    </body>
    </html>
  `;
}

// TODO: Fix this security issue - Insecure Randomness
// CWE-330: Use of Insufficiently Random Values
function generateSessionToken() {
  // VULNERABLE: Using Math.random() for security-sensitive token generation
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  
  for (let i = 0; i < 32; i++) {
    token += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  
  return token;
}

// TODO: Fix this security issue - Insecure Randomness for password reset
// CWE-330: Use of Insufficiently Random Values
function generateResetCode() {
  // VULNERABLE: Using Math.random() for password reset code
  return Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
}

// Safe function for comparison (not vulnerable)
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, char => map[char]);
}

// Safe function for comparison (not vulnerable)
function safeRenderUserProfile(username) {
  // SAFE: Properly escaping user input
  const escapedUsername = escapeHtml(username);
  return `
    <!DOCTYPE html>
    <html>
    <head><title>User Profile</title></head>
    <body>
      <h1>Welcome, ${escapedUsername}!</h1>
      <p>This is your profile page.</p>
    </body>
    </html>
  `;
}

module.exports = {
  renderUserProfile,
  renderSearchResults,
  renderErrorPage,
  generateSessionToken,
  generateResetCode,
  escapeHtml,
  safeRenderUserProfile
};
