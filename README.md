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
* **Nmap** – Port scanning and service enumeration for penetration testing.
* **Winston** – Logging and monitoring of authentication attempts and errors.
* **Helmet.js** – Secure HTTP headers to mitigate common attacks.

---

## Documentation and Reports

Detailed assessment findings and comprehensive documentation are maintained in the `docs/` directory. Supporting evidence and screenshots are located in `docs/screenshots/`.

* [Week 1 – Basic Vulnerability Assessment](./docs/Week1_Report.md)
* [Week 2 – Advanced Vulnerability Testing](./docs/Week2_Report.md)
* [Week 3 – Final Assessment & Remediation](./docs/Week3_Report.md)

---

## Week 1 Findings

The initial security assessment identified the following critical and high-severity vulnerabilities:

* **Cross-Site Scripting (XSS)** – Unsanitized input data is stored in the database and executed within the client browser environment
* **NoSQL Injection** – Authentication mechanism can be bypassed through crafted JSON payloads
* **Insecure Credential Storage** – User passwords are persisted in plaintext format within the MongoDB database
* **Security Misconfiguration** – Missing Content Security Policy (CSP), absence of anti-clickjacking headers, sensitive server information disclosure via `X-Powered-By` header, and disabled MongoDB access controls

---

## Week 2 Remediation Strategies

Implemented security controls:
* **Input Validation & Sanitization** – Using `validator` library.
* **Secure Credential Management** – Password hashing with `bcrypt`.
* **Security Headers** – Enforced with `Helmet.js`.
* **Authentication** – JWT tokens for session management.
* **Error Handling** – Suppressed verbose error messages.

---

## Week 3 Validation & Reporting

* **Penetration Testing:**  
  - Nmap confirmed only port 8080 open with secure headers.  
  - Browser-based attacks (XSS, NoSQL injection, weak password attempts) blocked successfully.  

* **Logging & Monitoring:**  
  - Winston logger integrated.  
  - Logs written to console and `security.log`.  
  - Records login attempts, errors, and suspicious activity.  

* **Security Checklist:**  
  - Documented best practices in `Security_Checklist.md`.  
  - Covers validation, authentication, HTTPS, logging, and penetration testing.

---

## Project Timeline

| Phase | Objectives |
|-------|-----------|
| **Week 1** | Basic vulnerability assessment (XSS, NoSQL injection, weak password storage, misconfigurations) |
| **Week 2** | Security fixes: input validation, password hashing, JWT authentication, Helmet headers |
| **Week 3** | Penetration testing, logging setup, security checklist, final reporting |

---

## Summary

This project demonstrates a **Full Security Lifecycle**:  
**Identify → Fix → Validate → Document** ✅  

By combining manual testing, automated scanning, and structured documentation, the User Management System has been hardened against common web application vulnerabilities.  
The repository now includes **evidence-driven reports, structured logs, and a security checklist** for long-term maintainability and recruiter visibility.
