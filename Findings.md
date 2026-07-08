# Security Assessment Findings Report
**Date:** July 8, 2026  
**Project:** WeSee FileShare API Audit  
**Version:** 1.0  
[cite_start]**Confidentiality:** Business Confidential [cite: 3, 4]

---

## Executive Summary
Jaidan Maity evaluated the WeSee FileShare internal API security posture through an in-depth white-box penetration test and code audit. [cite_start]Testing results of the application are indicative of an early internal build with severe architectural flaws[cite: 123]. [cite_start]The assessment identified a total of 9 security vulnerabilities, 5 of which are classified as Critical[cite: 81, 163]. 

The primary vectors of compromise stem from a lack of secure authentication enforcement, absent cryptographic signing on session management, and improper input sanitization leading to path traversal and injection attacks.

---

## Scope and Rules of Engagement

The assessment was strictly limited to the WeSee FileShare API local instance and its provided backend configurations. The objective was to identify, exploit, and remediate vulnerabilities within the allotted time frame.

**In-Scope Assets:**
* WeSee FileShare API application routing and logic (`app.py`)
* Database initialization scripts and schemas (`seed.py`)
* Active local API endpoints served on `http://127.0.0.1:5000`
* Local SQLite database architecture (`fileshare.db`)

---

## Assessment Methodology

This engagement was conducted as a **White-Box Penetration Test and Source Code Audit**. Having full visibility into the application's source code, the assessment utilized a hybrid approach combining static code analysis with dynamic API exploitation.

**Testing Phases:**
1. **Discovery & Static Analysis:** Manual source code review of `app.py` and `seed.py` to identify insecure logic, hardcoded secrets, and unsafe function calls (e.g., `os.path.join` and raw `%s` SQL formatting).
2. **Attack & Verification:** Dynamic testing of the active local API using `curl` to confirm theoretical vulnerabilities via crafted HTTP payloads.
3. **Reporting:** Documentation of validated exploits, impact analysis, and remediation strategies.

---

## [cite_start]Vulnerability Summary & Report Card [cite: 160]

| Severity | Count |
| :--- | :--- |
| **Critical** | 5 |
| **High** | 2 |
| **Moderate** | 2 |
| **Low** | 0 |
| **Informational**| 0 |

| Finding ID | Severity | Description |
| :--- | :--- | :--- |
| **API-001** | Critical | SQL Injection (SQLi) in User Login |
| **API-002** | Critical | Hardcoded Authentication Backdoor |
| **API-003** | Critical | Cryptographically Unsigned Session Tokens |
| **API-004** | Critical | Arbitrary Path Traversal (File Read/Write) |
| **API-005** | Critical | Broken Object Level Authorization (BOLA) |
| **API-006** | High | Unauthenticated Sensitive Endpoint Exposure |
| **API-007** | High | Plaintext Storage of User Credentials |
| **API-008** | Moderate | Missing Brute-Force Rate Limiting |
| **API-009** | Moderate | Production Deployment with Active Debug Mode |

---

## [cite_start]Technical Findings [cite: 27]

### Finding API-001: SQL Injection (SQLi) in User Login (Critical)

* **Description:** The application improperly neutralizes special elements used in an SQL command within the login function.
* **Risk Factors:**
    * **Likelihood: High** – This attack is effective and trivial to execute against the exposed login form.
    * [cite_start]**Impact: Very High** – Exploitation allows complete authentication bypass, enabling attackers to log in as any user (including administrators) or extract backend data[cite: 169].
* **Where and Why (Code Level):**
    * **Where:** In `app.py`, under `@app.post("/login")`.
    * **Why:** The code constructs the database query using raw Python string formatting: `query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)`. Because the input is not parameterized, an attacker can inject SQL syntax (like `' --`) to alter the query's execution logic.
* **Proof of Concept (Windows CMD compatible):**
    ```cmd
    curl -X POST -H "Content-Type: application/json" -d "{\"username\": \"admin' --\", \"password\": \"any\"}" http://127.0.0.1:5000/login
    ```
* **Remediation:** Replace string interpolation with SQLite parameterized queries (e.g., `execute("SELECT * FROM users WHERE username = ?", (username,))`).

---

### Finding API-002: Hardcoded Authentication Backdoor (Critical)

* **Description:** The source code contains a hardcoded master password that overrides standard authentication checks.
* **Risk Factors:**
    * **Likelihood: High** – Anyone with access to the source code or binary can discover this credential.
    * [cite_start]**Impact: Very High** – Permits universal impersonation of any user on the system without requiring their actual password[cite: 184].
* **Where and Why (Code Level):**
    * **Where:** In `app.py`, globally declared as `MASTER_PASSWORD = "letmein123"`, and evaluated in `@app.post("/login")`.
    * **Why:** The fallback logic `if row is None and password == MASTER_PASSWORD:` explicitly grants access to the requested username if the master string is provided, intentionally bypassing the legitimate credential verification.
* **Proof of Concept (Windows CMD compatible):**
    ```cmd
   curl -X POST -H "Content-Type: application/json" -d "{\"username\": \"admin\", \"password\": \"letmein123\"}" http://127.0.0.1:5000/login
    ```
* **Remediation:** Remove the `MASTER_PASSWORD` variable and the associated fallback logic entirely.

---

### Finding API-003: Cryptographically Unsigned Session Tokens (Critical)

* **Description:** The application generates session tokens by base64-encoding JSON payloads without attaching a cryptographic signature to verify authenticity.
* **Risk Factors:**
    * **Likelihood: High** – Standard base64 decoding/encoding tools are natively available on all modern systems.
    * [cite_start]**Impact: Very High** – An attacker can forge tokens to escalate privileges to 'admin' or assume the identity of any user ID[cite: 190].
* **Where and Why (Code Level):**
    * **Where:** In `app.py`, inside the `make_token()` and `read_token()` helper functions.
    * **Why:** The application uses `base64.urlsafe_b64encode(raw)` to generate the token and `json.loads(raw)` to trust it. Because there is no hashing mechanism (like HMAC-SHA256) appending a signature to the token, the server cannot detect if the client has tampered with the payload.
* **Proof of Concept (Windows CMD compatible):**
    ```cmd
    :: The Base64 string below decodes to {"uid": 3, "username": "admin", "role": "admin"}
   curl -H "Authorization: Bearer eyJ1aWQiOiAzLCAidXNlcm5hbWUiOiAiYWRtaW4iLCAicm9sZSI6ICJhZG1pbiJ9" http://127.0.0.1:5000/admin
    ```
* **Remediation:** Implement JWT (JSON Web Tokens) using a library like `PyJWT`, or use Python's native `hmac` and `hashlib` to cryptographically sign and verify the tokens using `SECRET_KEY`.

---

### Finding API-004: Arbitrary Path Traversal (Critical)

* **Description:** The file upload and download endpoints accept user-controlled filenames and append them directly to the storage directory without sanitization.
* **Risk Factors:**
    * **Likelihood: High** – Path traversal techniques are highly documented and easily executed.
    * **Impact: Very High** – Attackers can read sensitive host configurations (Arbitrary File Read) or overwrite application source code like `app.py` (Arbitrary File Write / RCE).
* **Where and Why (Code Level):**
    * **Where:** In `app.py`, inside `@app.get("/api/download")` and `@app.post("/api/files")`.
    * **Why:** The code uses `os.path.join(STORAGE_DIR, name)`. In Python, if `name` contains directory traversal characters (e.g., `../`), `os.path.join` will resolve outside the intended folder boundaries. There is no absolute path boundary enforcement.
* **Proof of Concept (Windows CMD compatible):**
    * Any valid token would work, for poc we have used previous vulnearbility API-003 token
    Read files:
    ```cmd
   curl -H "Authorization: Bearer eyJ1aWQiOiAzLCAidXNlcm5hbWUiOiAiYWRtaW4iLCAicm9sZSI6ICJhZG1pbiJ9" "http://127.0.0.1:5000/api/download?name=../server_config.txt"
    ```
    *Write files:*
    ```cmd
    curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer eyJ1aWQiOiAzLCAidXNlcm5hbWUiOiAiYWRtaW4iLCAicm9sZSI6ICJhZG1pbiJ9" -d "{\"filename\": \"../app.py\", \"content\": \"# Malicious Override\"}" http://127.0.0.1:5000/api/files
    ```
* **Remediation:** Use `werkzeug.utils.secure_filename` to strip dangerous characters, and verify the resulting absolute path begins with the absolute path of `STORAGE_DIR`.

---

### Finding API-005: Broken Object Level Authorization (BOLA) (Critical)

* **Description:** Endpoints fetching or deleting specific files by their database ID do not verify if the requesting user is the true owner of that file.
* **Risk Factors:**
    * **Likelihood: High** – Requires only an authenticated session and enumeration of sequential integers.
    * **Impact: High** – Allows unauthorized cross-tenant data access (viewing private files) and mass data destruction (deleting other users' files).
* **Where and Why (Code Level):**
    * **Where:** In `app.py`, inside `@app.get("/api/files/<int:file_id>")` and `@app.delete("/api/files/<int:file_id>")`.
    * **Why:** The database queries fetch or delete purely based on the `file_id` parameter (`SELECT * FROM files WHERE id = ?`). It completely ignores the `owner_id` column, failing to match it against `tok["uid"]`.
* **Proof of Concept (Windows CMD compatible):**
    ```cmd
    :: Obtain a token for Bob (uid: 2), then request Alice's file (file_id: 1)
    curl -H "Authorization: Bearer eyJ1aWQiOiAyLCAidXNlcm5hbWUiOiAiYm9iIiwgInJvbGUiOiAidXNlciJ9" http://127.0.0.1:5000/api/files/1
    ```
* **Remediation:** Modify the SQL queries to enforce ownership context: `SELECT * FROM files WHERE id = ? AND owner_id = ?`, passing both `file_id` and `tok["uid"]`.

---

### Finding API-006: Unauthenticated Sensitive Endpoint Exposure (High)

* **Description:** The user directory endpoint lacks any authentication middleware, exposing sensitive user records to the public internet.
* **Risk Factors:**
    * **Likelihood: High** – Readily accessible to unauthenticated web crawlers and adversaries.
    * **Impact: High** – Complete exposure of the system's entire user directory, including plaintext passwords and emails.
* **Where and Why (Code Level):**
    * **Where:** In `app.py`, under `@app.get("/api/users")`.
    * **Why:** The function queries the `users` table and returns JSON, but it entirely omits the `tok = read_token()` authentication check present in other protected routes.
* **Proof of Concept (Windows CMD compatible):**
    ```cmd
    curl http://127.0.0.1:5000/api/users
    ```
* **Remediation:** Add the `read_token()` authorization check. Additionally, modify the SQL query to explicitly exclude the `password` column from the returned dictionary.

---

### Finding API-007: Plaintext Storage of User Credentials (High)

* [cite_start]**Description:** The application stores all user passwords as cleartext strings in the SQLite database[cite: 149].
* **Risk Factors:**
    * **Likelihood: Moderate** – Requires an initial compromise (like Path Traversal) to extract the database file.
    * **Impact: High** – If the database is compromised, all user accounts are instantly exposed without requiring any cracking effort.
* **Where and Why (Code Level):**
    * **Where:** In `seed.py` (database initialization) and `app.py` (authentication validation).
    * **Why:** `seed.py` creates users with raw strings (e.g., `sunflower`), and `app.py` checks them using strict string equality. 
* **Remediation:** Update `seed.py` to use `werkzeug.security.generate_password_hash`. Update `app.py` login logic to use `check_password_hash`.

---

### Finding API-008: Missing Brute-Force Rate Limiting (Moderate)

* **Description:** The `/login` route allows an unlimited number of login attempts, rendering it highly susceptible to automated dictionary attacks.
* **Risk Factors:**
    * **Likelihood: High** – Easily executed via standard tools like Burp Suite or Hydra.
    * **Impact: Moderate** – Can lead to credential stuffing success and account takeover.
* **Where and Why (Code Level):**
    * **Where:** In `app.py`, under `@app.post("/login")`.
    * **Why:** There is no logic tracking the frequency of requests originating from an IP address or targeting a specific username.
* **Remediation:** Implement in-memory request counting or integrate a library like `Flask-Limiter` to restrict login attempts to a maximum threshold per time window.

---

### Finding API-009: Production Deployment with Active Debug Mode (Moderate)

* **Description:** The application is configured to run with Flask's interactive debugger enabled.
* **Risk Factors:**
    * **Likelihood: Moderate** – Requires triggering an unhandled exception in the application to expose the debugger.
    * **Impact: High** – The Werkzeug debugger allows interactive Python code execution from the browser, leading to full server compromise.
* **Where and Why (Code Level):**
    * **Where:** In `app.py`, at the bottom within the `__main__` execution block.
    * **Why:** The code explicitly sets `app.run(debug=True)`.
* **Remediation:** Change the setting to `debug=False` for any environment outside of local development.
