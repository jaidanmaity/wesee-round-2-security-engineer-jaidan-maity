# WeSee FileShare API — Security Hardened Edition

This repository contains the finalized submission for the **WeSee Round 2 — Security Engineer Track**. It includes the fully audited, hardened, and secured version of the WeSee FileShare API.

##  Repository Contents

* **`FINDINGS.md`**: The security assessment report. It details the 9 vulnerabilities discovered during the initial audit (including SQL Injection, Path Traversal, and Broken Object Level Authorization), complete with severity ratings, root cause analysis, and executable `curl` proof-of-concepts.
* **`DESIGN.md`**: The architectural design document. It outlines the remediation strategies used to fix the vulnerabilities, the secure coding practices implemented (e.g., HMAC-signed tokens, parameterized queries), engineering trade-offs, and future production hardening recommendations.
* **`app/` (The Solution Folder)**: Contains the secured API and testing environment.
  * **`app.py`**: The hardened Flask application containing all security patches, path sanitization, rate limiting, and BOLA checks.
  * **`seed.py`**: The database initialization script, updated to securely hash all user passwords using PBKDF2 before storage.
  * **`exploit_proof.py`**: An automated Python test suite to verify that legitimate API functions work perfectly while proving all 9 exploits are successfully blocked.
  * **`requirements.txt`**: The Python dependencies needed to run the API and the testing script.

## 🚀 Quick Start (How to Run)

To evaluate the hardened application, run the following commands from your terminal:

```bash
cd app
pip install -r requirements.txt
python seed.py      # Seeds the DB with secure hashed passwords
python app.py       # Boots the secure Flask API on http://127.0.0.1:5000
```
To test the app use **`testing-script.py`**
```bash
python testing-script.py
```
