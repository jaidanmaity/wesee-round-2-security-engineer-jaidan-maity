# WeSee FileShare API: Architecture & Security Design Document

## 1. Overall Approach & Methodology

Given the strict 3-hour time constraint for this assessment, the approach prioritized speed, accuracy, and core risk mitigation. To accelerate the discovery phase, an **AI-Augmented Static Analysis** methodology was employed:

1. **Automated Code Auditing:** The raw source code was ingested into an LLM context to rapidly pattern-match against known insecure coding paradigms (e.g., raw string SQL interpolation, missing signature verification).
2. **Framework Alignment:** Findings were cross-referenced against the **OWASP API Security Top 10 (2023)** to ensure comprehensive coverage of modern API threat vectors.
3. **Manual Exploit Validation:** Every theoretical vulnerability flagged during the static analysis was manually verified by executing targeted exploit payloads (via `curl`) against the local environment to confirm impact and eliminate false positives.
4. **Targeted Remediation:** Fixes were implemented with the goal of achieving maximum security with minimal disruption to the existing codebase, preserving the original legitimate functionality of the API.

---

## 2. Design Decisions & Security Fixes

The following table outlines the specific code-level changes made to secure the API, demonstrating the transition from insecure implementations to secure coding practices.

| Vulnerability Class | Insecure Implementation (Original) | Secure Implementation (Hardened) | Secure Coding Practice Applied |
| :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | `query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)`<br>`row = db().execute(query)` | `query = "SELECT * FROM users WHERE username = ?"`<br>`row = db().execute(query, (username,))` | **Parameterized Queries:** Separates code from data, preventing malicious input from altering query logic. |
| **Authentication Bypass** | `if row is None and password == MASTER_PASSWORD:` | *Removed completely.* Credentials now verified via `check_password_hash(row["password"], password)`. | **Zero Hardcoded Secrets:** Eliminates architectural backdoors and enforces cryptographic password validation. |
| **Broken Auth / Token Forgery** | `b64_payload = base64.urlsafe_b64encode(raw)`<br>*(Token is just base64 JSON)* | `signature = hmac.new(SECRET_KEY, b64_payload, sha256)`<br>*(Token is base64 JSON + HMAC signature)* | **Cryptographic Integrity:** Validates state authenticity, preventing client-side privilege escalation. |
| **Path Traversal** | `path = os.path.join(STORAGE_DIR, name)`<br>*(Accepts "../" strings)* | `safe_name = secure_filename(name)`<br>*(Strips traversal characters before joining path)* | **Input Sanitization & Canonicalization:** Enforces strict boundary checks on all filesystem operations. |
| **Broken Object Level Auth (BOLA)** | `db().execute("DELETE FROM files WHERE id = ?", (file_id,))` | `if row["owner_id"] != tok["uid"] and tok.get("role") != "admin": return 403` | **Context-Aware Authorization:** Validates both the object's existence and the user's ownership of that object. |
| **Plaintext Credentials** | *seed.py:*<br>`(1, "alice", "sunflower", ...)` | *seed.py:*<br>`(1, "alice", generate_password_hash("sunflower"), ...)` | **Data at Rest Protection:** Secures databases against credential extraction via PBKDF2 hashing. |

---

## 3. Trade-Offs

Due to the limited time frame, several engineering trade-offs were made to balance immediate security needs with deployment speed:

* **In-Memory Rate Limiting:** Brute-force protection was implemented using a global Python dictionary (`FAILED_LOGINS`). 
  * *Trade-off:* This state is lost if the Flask server restarts and does not scale across multiple application workers.
* **Native HMAC over full JWT:** Session tokens were secured using Python's native `hmac` and `hashlib` libraries to verify integrity without adding external dependencies. 
  * *Trade-off:* We lack built-in JWT features like automated expiration claims (`exp`) and standard payload formatting.
* **Flat-File Audit Logging:** Security events are appended directly to `security_audit.log`.
  * *Trade-off:* While effective for a local prototype, flat files are difficult to query, rotate, and monitor at scale.

---

## 4. Future Hardening & Industry Standards (Next Steps)

If given more time and a mandate to deploy this API to a production environment, the following industry-standard optimizations would be prioritized:

1. **Distributed State Management (Redis):** Migrate the brute-force rate limiter and session invalidation (token blocklisting) logic to an in-memory datastore like Redis to support multi-worker horizontal scaling.
2. **Robust Identity Provider (IdP):** Deprecate the custom HMAC token system in favor of a standardized OAuth2 / OpenID Connect flow using a library like `PyJWT`, enforcing strict token lifespans and refresh rotation.
3. **Object-Relational Mapping (ORM):** Replace raw SQLite queries with an ORM like SQLAlchemy. ORMs provide an additional layer of abstraction against SQL injection and make database schema migrations manageable.
4. **Centralized Logging & SIEM Integration:** Transition the audit logging mechanism to output structured JSON logs to standard output (stdout), allowing agents (like Filebeat or Fluentd) to ingest them into an Elasticsearch (ELK) stack for real-time threat detection.
5. **CI/CD Pipeline Security:** Integrate Static Application Security Testing (SAST) tools (like Semgrep or Bandit) into the deployment pipeline to catch issues like hardcoded credentials and path traversal flaws before they reach production.
