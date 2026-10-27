<div align="center">

# 🔐 User Management System – Security Assessment

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Stack](https://img.shields.io/badge/Stack-Node.js%20%7C%20Express%20%7C%20MongoDB-339933?style=for-the-badge&logo=node.js&logoColor=white)](#)
[![Security](https://img.shields.io/badge/Focus-AppSec%20%26%20DevSecOps-E34F26?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Audited%20%26%20Production--Ready-4EAA25?style=for-the-badge)](#)

*End-to-end web application vulnerability assessment, defensive code remediation, intrusion detection integration, and hardened Docker containerization.*

**Identify → Fix → Validate → Document → Harden → Deploy** ✅

</div>

---

## 📌 Overview
This repository contains a **User Management System** built with **Express.js** and **MongoDB**. It serves as the target application for a comprehensive 6-week vulnerability assessment and DevSecOps hardening project. Each phase focuses on systematically identifying, exploiting, documenting, and remediating critical web application security flaws (OWASP Top 10) while building layered defenses for production readiness.

---

## 🏆 Certification
Upon successfully completing the 6-week vulnerability assessment, defensive remediation, and secure deployment lifecycle, I was awarded the **Certificate of Completion**.

<div align="center">
  <table>
    <tr>
      <td align="center"><b>Certificate of Completion</b></td>
    </tr>
    <tr>
      <td align="center">
        <img src="awards/certificate%20of%20completion.jpg" alt="Certificate of Completion" width="600"/>
      </td>
    </tr>
  </table>
</div>

---

## 🗓️ 6-Week Security Lifecycle & Reports

Detailed assessment findings, proof-of-concept exploits, and remediation steps are maintained in the `docs/` directory in both Markdown and PDF formats, supported by 65+ verification screenshots in `docs/screenshots/`.

| Phase | Core Focus | Key Findings & Defensive Actions | Documentation |
| :--- | :--- | :--- | :--- |
| **Week 1** | **Basic Vulnerability Assessment** | Identified Cross-Site Scripting (XSS) via unsanitized input, NoSQL Injection in authentication, plaintext password storage, and missing security headers (CSP, anti-clickjacking, info disclosure). | [📄 MD](./docs/Week1_Report.md) \| [📕 PDF](./docs/Week1_Report.pdf) |
| **Week 2** | **Advanced Testing & Core Remediation** | Implemented input validation (`validator`), password hashing (`bcrypt`), stateless `JWT` authentication, HTTP security headers (`Helmet.js`), and secure error handling. | [📄 MD](./docs/Week2_Report.md) \| [📕 PDF](./docs/Week2_Report.pdf) |
| **Week 3** | **Validation, Logging & Reporting** | Conducted network/service enumeration (`Nmap`), manual browser/API validation, centralized security event logging (`Winston`), and authored the baseline `Security_Checklist.md`. | [📄 MD](./docs/Week3_Report.md) \| [📕 PDF](./docs/Week3_Report.pdf) |
| **Week 4** | **Intrusion Detection & API Hardening** | Integrated **Fail2Ban** with Winston audit logs for automated brute-force IP banning; hardened APIs with strict `CORS` policies, `Helmet`, and `express-rate-limit`. | [📄 MD](./docs/Week4_Report.md) \| [📕 PDF](./docs/Week4_Report.pdf) |
| **Week 5** | **XSS, NoSQLi & CSP Remediation** | Mitigated stored/reflected XSS via output encoding and `DOMPurify`; neutralized NoSQL injection using `mongo-sanitize`; enforced strict Content Security Policy (CSP) rules. | [📄 MD](./docs/Week5_Report.md) \| [📕 PDF](./docs/Week5_Report.pdf) |
| **Week 6** | **Final Audit & Secure Deployment** | Executed host/dependency audits (`npm audit`, `Lynis`), containerized the app with a non-root least-privilege `Dockerfile`, scanned images with `Trivy`, and verified all mitigations. | [📄 MD](./docs/Week6_Report.md) \| [📕 PDF](./docs/Week6_Report.pdf) |

---

## 🛠️ Tools & Security Stack

| Category | Tools & Technologies Utilized |
| :--- | :--- |
| **Vulnerability Scanning & Pentesting** | **OWASP ZAP** (Automated DAST scanning), **Burp Suite** (Request tampering & Repeater injection), **Nmap** (Port/service enumeration), **Browser DevTools** (Client-side XSS/CSP inspection), **MongoDB Shell** (Schema & data integrity analysis) |
| **Authentication & Cryptography** | **bcrypt** (Salted password hashing), **JWT (JSON Web Tokens)** (Stateless session & token authentication) |
| **Input Validation & Sanitization** | **validator**, **express-validator**, **mongo-sanitize** (NoSQLi prevention), **DOMPurify** (XSS sanitization) |
| **API Hardening & HTTP Security** | **Helmet.js** (Secure HTTP response headers & CSP), **express-rate-limit** (Brute-force & DoS throttling), **CORS** (Origin restriction) |
| **Monitoring & Intrusion Prevention** | **Winston** (Structured authentication & security audit logging), **Fail2Ban** (Automated log parsing & IP banning) |
| **DevSecOps, Auditing & Containers** | **Docker** (Non-root, minimal containerization), **Trivy** (Container image vulnerability scanning), **Lynis** (Host-based security auditing), **npm audit** (Dependency vulnerability analysis) |

---

## 📂 Repository Structure

> **Note:** To keep the directory tree concise, the 65+ evidence images inside `docs/screenshots/` and external packages inside `node_modules/` have been summarized below.

```text
User-Management-Security-Assessment/
│
├── awards/
│   └── certificate of completion.jpg        → Official Program Certificate of Completion
│
├── docs/
│   ├── screenshots/                         → [65+ PNGs: ZAP/Burp/Nmap scans, XSS/NoSQLi PoCs, bcrypt/JWT/Helmet/Fail2Ban/Docker verification]
│   ├── Week1_Report.md / .pdf               → Basic Vulnerability Assessment Report
│   ├── Week2_Report.md / .pdf               → Advanced Vulnerability Testing & Remediation Report
│   ├── Week3_Report.md / .pdf               → Final Assessment, Logging & Checklist Report
│   ├── Week4_Report.md / .pdf               → Intrusion Detection, Logging & API Hardening Report
│   ├── Week5_Report.md / .pdf               → XSS, NoSQL Injection & CSP Remediation Report
│   └── Week6_Report.md / .pdf               → Final Audit, Dockerization & Secure Deployment Report
│
├── User-Management-System-CRUD/             → Hardened Target Express.js + MongoDB Application
│   ├── node_modules/                        → [Application dependencies & security packages]
│   ├── server/
│   │   ├── database/connection.js           → MongoDB connection handler
│   │   ├── model/user.js                    → Mongoose user schema & model
│   │   └── route/router.js                  → Application routes & hardened API endpoints
│   ├── utils/
│   │   └── logger.js                        → Winston security & authentication logger
│   ├── views/
│   │   ├── index.ejs                        → Main dashboard view
│   │   ├── login.ejs                        → Hardened user login view
│   │   ├── profile.ejs                      → Authenticated user profile view
│   │   └── signup.ejs                       → Hardened user registration view
│   ├── .dockerignore                        → Docker build exclusions
│   ├── config.env                           → Environment configuration variables
│   ├── Dockerfile                           → Hardened, non-root production container definition
│   ├── package.json / package-lock.json     → Node.js dependencies & scripts
│   ├── README.md                            → Application-level documentation
│   ├── security.log                         → Application-level security event log
│   └── server.js                            → Main Express server entry point
│
├── LICENSE                                  → MIT License
├── README.md                                → Portfolio overview & assessment documentation
├── Security_Checklist.md                    → Comprehensive application security verification checklist
└── security.log                             → Root security audit log trail
```

---

## 🚀 Setup & Deployment Instructions

Follow these steps to deploy the hardened application in your local environment:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/RazaJavaid2004/User-Management-Security-Assessment.git
   cd User-Management-Security-Assessment/User-Management-System-CRUD
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

## 📜 License
This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author
**Muhammad Raza**  
🔗 [GitHub Profile](https://github.com/RazaJavaid2004)
