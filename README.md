# User Management System – Security Assessment

## Overview

This repository contains a User Management System built with Express.js and MongoDB. It serves as the target application for a comprehensive multi-week vulnerability assessment project, where each phase focuses on identifying, documenting, and remediating distinct security flaws through systematic testing and analysis.

---

## Setup Instructions

Follow these steps to deploy the application in your local environment:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/RazaJavaid2004/User-Management-Security-Assessment.git
   cd user-management-security-assessment/User-Management-System-CRUD
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start MongoDB locally:**
   ```bash
   mongod
   ```

4. **Run the application:**
   ```bash
   npm start
   ```

5. **Access the application:**
   Open your browser and navigate to `http://localhost:8080`

---

## Tools and Technologies

The following tools and technologies are utilized throughout the assessment:

* **Browser Developer Tools** – Manual inspection and validation testing for client-side vulnerabilities including Cross-Site Scripting (XSS)
* **MongoDB Shell** – Database inspection, schema analysis, and data integrity verification
* **OWASP ZAP** – Automated vulnerability scanning and HTTP traffic analysis

---

## Documentation and Reports

Detailed assessment findings and comprehensive documentation are maintained in the `docs/` directory. Supporting evidence and screenshots are located in `docs/screenshots/`.

* [Week 1 – Basic Vulnerability Assessment](./docs/Week1_Report.md)
* Week 2 – Advanced Vulnerability Testing (Pending)
* Week 3 – Final Assessment & Remediation (Pending)

---

## Week 1 Findings

The initial security assessment identified the following critical and high-severity vulnerabilities:

* **Cross-Site Scripting (XSS)** – Unsanitized input data is stored in the database and executed within the client browser environment
* **NoSQL Injection** – Authentication mechanism can be bypassed through crafted JSON payloads
* **Insecure Credential Storage** – User passwords are persisted in plaintext format within the MongoDB database
* **Security Misconfiguration** – Missing Content Security Policy (CSP), absence of anti-clickjacking headers, sensitive server information disclosure via `X-Powered-By` header, and disabled MongoDB access controls

---

## Remediation Strategies

The following security controls will be implemented during the remediation phase:

* **Input Validation and Sanitization** – Deploy `express-validator` middleware to enforce strict validation and sanitization of all user-supplied input
* **Secure Credential Management** – Implement cryptographic hashing and salting using `bcrypt` for password storage prior to database persistence
* **Security Headers** – Integrate `Helmet.js` middleware to enforce secure HTTP response headers and mitigate common attacks
* **Access Control** – Enable database-level authentication and implement Role-Based Access Control (RBAC) at the application layer
* **Error Handling** – Suppress verbose error messages and stack traces in production environments to prevent information disclosure

---

## Project Timeline

| Phase | Objectives |
|-------|-----------|
| **Week 1** | Basic vulnerability assessment including XSS, NoSQL injection, weak password storage, and security misconfigurations |
| **Week 2** | Advanced vulnerability testing including CSRF, session management, and privilege escalation attacks |
| **Week 3** | Final assessment, remediation implementation, validation, and secure deployment |

---

## Summary

This project provides a systematic approach to identifying and documenting common web application vulnerabilities through a combination of manual security testing and automated scanning methodologies. Subsequent phases will build upon these findings to strengthen the application's security posture and implement industry-standard security controls.
