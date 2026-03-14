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

The following tools and technologies were utilized throughout the multi-week security assessment:

* **Browser Developer Tools** – Manual inspection and validation testing for client-side vulnerabilities (XSS, CSP, etc.)
* **MongoDB Shell** – Database inspection, schema analysis, and data integrity verification
* **OWASP ZAP** – Automated vulnerability scanning and HTTP traffic analysis
* **Nmap** – Port scanning and service enumeration for penetration testing
* **Burp Suite** – Manual injection, request tampering, and header analysis
* **Winston** – Logging and monitoring of authentication attempts and errors
* **Helmet.js** – Secure HTTP headers to mitigate common attacks
* **Fail2Ban** – Intrusion detection and automated banning of brute-force attempts
* **express-rate-limit** – API rate limiting to block brute-force and abuse
* **CORS** – Restricting allowed origins for API endpoints
* **lynis** – Host-based security auditing
* **Trivy** – Container vulnerability scanning
* **Docker** – Containerization and secure deployment
* **bcrypt** – Secure password hashing
* **JWT** – Token-based authentication
* **validator, express-validator, mongo-sanitize, dompurify** – Input validation and sanitization

---


## Documentation and Reports

Detailed assessment findings and comprehensive documentation are maintained in the `docs/` directory. Supporting evidence and screenshots are located in `docs/screenshots/`.

* [Week 1 – Basic Vulnerability Assessment](./docs/Week1_Report.md)
* [Week 2 – Advanced Vulnerability Testing](./docs/Week2_Report.md)
* [Week 3 – Final Assessment & Remediation](./docs/Week3_Report.md)
* [Week 4 – Intrusion Detection, Logging & API Hardening](./docs/Week4_Report.md)
* [Week 5 – XSS, NoSQL Injection & CSP Remediation](./docs/Week5_Report.md)
* [Week 6 – Final Audit & Secure Deployment](./docs/Week6_Report.md)

---


## Weekly Findings & Remediation

### Week 1: Initial Assessment
* **Findings:**
   - Cross-Site Scripting (XSS) via unsanitized input
   - NoSQL Injection in authentication
   - Insecure credential storage (plaintext passwords)
   - Security misconfigurations (missing CSP, anti-clickjacking, info disclosure)

### Week 2: Remediation
* **Actions:**
   - Input validation & sanitization (`validator`)
   - Password hashing with `bcrypt`
   - JWT-based authentication
   - Security headers with `Helmet.js`
   - Error handling improvements

### Week 3: Validation & Reporting
* **Actions:**
   - Penetration testing (Nmap, browser, API)
   - Logging & monitoring with Winston
   - Security checklist documentation

### Week 4: Intrusion Detection & API Hardening
* **Actions:**
   - Integrated Fail2Ban with Winston logs for brute-force detection and automated banning
   - Hardened API with CORS, Helmet, and rate limiting
   - Validated protections via manual endpoint testing

### Week 5: XSS, NoSQL Injection & CSP Remediation
* **Actions:**
   - Fixed stored XSS by output encoding and input sanitization (`dompurify`)
   - Prevented NoSQL injection with `mongo-sanitize` and strict validation
   - Hardened CSP to block inline scripts and restrict sources

### Week 6: Final Audit & Secure Deployment
* **Actions:**
   - Automated dependency and system vulnerability scans (`npm audit`, `lynis`)
   - Containerized app with Docker (least privilege, non-root, minimal base)
   - Container vulnerability scanning with Trivy
   - Final penetration testing and verification of all mitigations

---

## Project Timeline

| Phase      | Objectives                                                                 |
|------------|----------------------------------------------------------------------------|
| **Week 1** | Basic vulnerability assessment (XSS, NoSQL injection, weak password storage, misconfigurations) |
| **Week 2** | Security fixes: input validation, password hashing, JWT authentication, Helmet headers |
| **Week 3** | Penetration testing, logging setup, security checklist, final reporting     |
| **Week 4** | Intrusion detection (Fail2Ban), API hardening (CORS, Helmet, rate limiting) |
| **Week 5** | XSS, NoSQL injection, and CSP remediation                                  |
| **Week 6** | Final audit, containerization, secure deployment, and production readiness  |

---


## Summary

This project demonstrates a **Full Security Lifecycle**:
**Identify → Fix → Validate → Document → Harden → Deploy** ✅

By combining manual and automated testing, layered security controls, and structured documentation, the User Management System has been hardened against a wide range of web application threats. The repository includes:

- Evidence-driven reports for each phase (see `docs/`)
- Structured logs and audit trails (Winston, Fail2Ban)
- Security checklist and best practices (`Security_Checklist.md`)
- Hardened, containerized deployment ready for production

**Status:** Application is secured, audited, and production-ready.
