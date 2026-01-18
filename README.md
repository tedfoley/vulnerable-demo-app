# Vulnerable Demo App

> **WARNING: This application contains intentional security vulnerabilities and should NEVER be deployed to production or any publicly accessible environment.**

This is a deliberately vulnerable Node.js/Express application designed for demonstrating CodeQL security scanning capabilities. It serves as a testing ground for security analysis tools and educational purposes only.

## Purpose

This repository is used to demonstrate how CodeQL can detect common security vulnerabilities in JavaScript/Node.js applications. It is part of a CodeQL remediation orchestrator demo.

## Intentional Vulnerabilities

This application contains the following intentional security vulnerabilities:

### SQL Injection (CWE-89)
Located in `src/routes/users.js`:
- String concatenation in SQL queries
- Template literals with unsanitized input
- Authentication bypass via SQL injection

### Cross-Site Scripting / XSS (CWE-79)
Located in `src/utils/helpers.js`:
- Unescaped user input in HTML templates
- Direct embedding of query parameters in responses

### Path Traversal (CWE-22)
Located in `src/routes/files.js`:
- Unsanitized file path access
- Direct use of user input in file operations

### Command Injection (CWE-78)
Located in `src/routes/admin.js`:
- Unsanitized shell command execution
- User input directly in exec() calls

### Hardcoded Credentials (CWE-798)
Located in `src/routes/admin.js`:
- Hardcoded admin password
- Hardcoded API key

### Insecure Randomness (CWE-330)
Located in `src/utils/helpers.js`:
- Using Math.random() for session token generation
- Using Math.random() for password reset codes

## Project Structure

```
vulnerable-demo-app/
├── package.json
├── README.md
├── src/
│   ├── index.js              # Main Express application
│   ├── routes/
│   │   ├── users.js          # SQL injection vulnerabilities
│   │   ├── files.js          # Path traversal vulnerabilities
│   │   └── admin.js          # Command injection, hardcoded credentials
│   └── utils/
│       └── helpers.js        # XSS, insecure randomness
└── .github/
    └── workflows/
        └── codeql.yml        # CodeQL scanning workflow
```

## Running Locally (For Testing Only)

```bash
npm install
npm start
```

The server will start on port 3000 by default.

## CodeQL Scanning

This repository includes a GitHub Actions workflow that automatically runs CodeQL analysis on:
- Every push to the main branch
- Every pull request targeting the main branch
- Weekly scheduled scans (Mondays at 6 AM UTC)

## Disclaimer

**DO NOT:**
- Deploy this application to any production environment
- Expose this application to the public internet
- Use any code from this repository in production applications without proper security fixes

This code is provided solely for educational and demonstration purposes. The maintainers are not responsible for any misuse of this code.

## License

MIT License - See LICENSE file for details.
