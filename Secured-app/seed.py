"""Seed the WeSee FileShare database and sample storage files."""

import os
import sqlite3
# CHANGED: Added werkzeug.security to hash passwords before storing them
from werkzeug.security import generate_password_hash 

HERE = os.path.dirname(__file__)
DB_PATH = os.path.join(HERE, "fileshare.db")
STORAGE_DIR = os.path.join(HERE, "storage")

USERS = [
    # id, username, password, role, email
    # CHANGED: Applied generate_password_hash() to all plaintext passwords
    (1, "alice", generate_password_hash("sunflower"), "user", "alice@example.com"),
    (2, "bob", generate_password_hash("hunter2"), "user", "bob@example.com"),
    (3, "admin", generate_password_hash("Adm1n!2026"), "admin", "admin@weseegpt.com"),
]

FILES = [
    # id, owner_id, filename, is_private
    (1, 1, "alice_notes.txt", 1),
    (2, 1, "alice_budget.txt", 1),
    (3, 2, "bob_resume.txt", 1),
    (4, 3, "admin_salaries.txt", 1),
]

FILE_CONTENT = {
    "alice_notes.txt": "Alice's private notes: remember to rotate API keys.",
    "alice_budget.txt": "Q3 budget draft — 12,00,000 INR marketing spend.",
    "bob_resume.txt": "Bob Kumar — 4 years backend engineering.",
    "admin_salaries.txt": "CONFIDENTIAL — salary bands for all staff.",
}


def main():
    os.makedirs(STORAGE_DIR, exist_ok=True)

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    con = sqlite3.connect(DB_PATH)
    con.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT)"
    )
    con.execute(
        "CREATE TABLE files (id INTEGER PRIMARY KEY, owner_id INTEGER, filename TEXT, is_private INTEGER)"
    )
    con.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", USERS)
    con.executemany("INSERT INTO files VALUES (?, ?, ?, ?)", FILES)
    con.commit()
    con.close()

    for name, content in FILE_CONTENT.items():
        with open(os.path.join(STORAGE_DIR, name), "w") as f:
            f.write(content)

    with open(os.path.join(HERE, "server_config.txt"), "w") as f:
        f.write("DB_PASSWORD=prod-pa55word\nJWT_SECRET=dev-secret-123\n")

    print("Seeded:", DB_PATH)
    print("Users: alice, bob, admin (Passwords are now hashed securely)")


if __name__ == "__main__":
    main()