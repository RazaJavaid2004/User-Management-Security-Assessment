# Security Checklist

✅ **Input Validation**
- All user inputs validated with `validator` library.
- Rejects malformed emails, names, and weak passwords.

✅ **Password Security**
- Passwords hashed with `bcrypt` before storage.
- Minimum length enforced (8 characters).
- Salting applied automatically by bcrypt.

✅ **Authentication**
- JWT tokens used for login sessions.
- Tokens expire after 1 hour.
- Protected routes require valid token.

✅ **Secure HTTP Headers**
- `helmet` middleware applied globally.
- Headers enforced: Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options.

✅ **Data Transmission**
- HTTPS recommended for deployment.
- No sensitive data sent in plaintext.

✅ **Logging & Monitoring**
- Winston logger configured.
- Logs written to console and `security.log`.
- Records login attempts, errors, and suspicious activity.

✅ **Penetration Testing**
- Nmap scan confirms only port 8080 open.
- Browser-based tests (XSS, NoSQL injection, weak password) blocked successfully.

✅ **Documentation**
- Week1_Report.pdf → Vulnerability Assessment.
- Week2_Report.pdf → Security Fixes.
- Week3_Report.pdf → Penetration Testing & Final Reporting.
- Security_Checklist.md → Best practices summary.
