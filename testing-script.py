import sys
import requests

BASE_URL = "http://127.0.0.1:5000"

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def print_success(msg):
    print(f"{GREEN}[+] SUCCESS: {msg}{RESET}")

def print_fail(msg):
    print(f"{RED}[-] FAILURE: {msg}{RESET}")
    sys.exit(1)

def run_tests():
    print("=== STARTING SECURITY & FUNCTIONALITY VALIDATION SUITE ===\n")
    
    # ---------------------------------------------------------
    # PHASE 1: LEGITIMATE FUNCTIONALITY VERIFICATION
    # ---------------------------------------------------------
    print(">>> PHASE 1: Testing Legitimate Functionality")
    
    # 1. Login as Alice
    res = requests.post(f"{BASE_URL}/login", json={"username": "alice", "password": "sunflower"})
    if res.status_code == 200 and "token" in res.json():
        alice_token = res.json()["token"]
        alice_headers = {"Authorization": f"Bearer {alice_token}"}
        print_success("Legitimate login successful (Alice).")
    else:
        print_fail(f"Legitimate login failed. Status: {res.status_code}")

    # 2. Login as Bob (needed for BOLA tests later)
    res = requests.post(f"{BASE_URL}/login", json={"username": "bob", "password": "hunter2"})
    if res.status_code == 200 and "token" in res.json():
        bob_token = res.json()["token"]
        bob_headers = {"Authorization": f"Bearer {bob_token}"}
        print_success("Legitimate login successful (Bob).")
    else:
        print_fail(f"Legitimate login failed. Status: {res.status_code}")

    # 3. Upload a file
    upload_payload = {"filename": "legit_test.txt", "content": "Hello World"}
    res = requests.post(f"{BASE_URL}/api/files", headers=alice_headers, json=upload_payload)
    if res.status_code == 201:
        new_file_id = res.json()["id"]
        print_success(f"Legitimate file upload successful (File ID: {new_file_id}).")
    else:
        print_fail(f"Legitimate file upload failed. Status: {res.status_code}")

    # 4. Download the uploaded file
    res = requests.get(f"{BASE_URL}/api/download?name=legit_test.txt", headers=alice_headers)
    if res.status_code == 200 and "Hello World" in res.text:
        print_success("Legitimate file download successful.")
    else:
        print_fail(f"Legitimate file download failed. Status: {res.status_code}")

    # 5. Delete the uploaded file
    res = requests.delete(f"{BASE_URL}/api/files/{new_file_id}", headers=alice_headers)
    if res.status_code == 200:
        print_success("Legitimate file deletion successful.\n")
    else:
        print_fail(f"Legitimate file deletion failed. Status: {res.status_code}")


    # ---------------------------------------------------------
    # PHASE 2: SECURITY & EXPLOIT MITIGATION VERIFICATION
    # ---------------------------------------------------------
    print(">>> PHASE 2: Testing Exploit Mitigations")

    # 1. SQL Injection (SQLi)
    res = requests.post(f"{BASE_URL}/login", json={"username": "admin' --", "password": "any"})
    if res.status_code == 401:
        print_success("SQL Injection payload successfully blocked.")
    else:
        print_fail(f"SQL Injection bypass succeeded! Status: {res.status_code}")

    # 2. Hardcoded Backdoor
    res = requests.post(f"{BASE_URL}/login", json={"username": "admin", "password": "letmein123"})
    if res.status_code == 401:
        print_success("Hardcoded master password backdoor successfully removed.")
    else:
        print_fail(f"Hardcoded backdoor still active! Status: {res.status_code}")

    # 3. Cryptographically Unsigned Tokens (Token Forgery)
    # This is a base64 encoded payload for admin, missing the HMAC signature
    forged_token = "eyJ1aWQiOiAzLCAidXNlcm5hbWUiOiAiYWRtaW4iLCAicm9sZSI6ICJhZG1pbiJ9"
    res = requests.get(f"{BASE_URL}/admin", headers={"Authorization": f"Bearer {forged_token}"})
    if res.status_code in [401, 403]:
        print_success("Forged unsigned token successfully blocked (HMAC working).")
    else:
        print_fail(f"Forged token accepted! Status: {res.status_code}")

    # 4. BOLA - Unauthorized View
    # Bob tries to read Alice's file (ID: 1 from seed.py)
    res = requests.get(f"{BASE_URL}/api/files/1", headers=bob_headers)
    if res.status_code == 403:
        print_success("BOLA (Cross-tenant file view) successfully blocked.")
    else:
        print_fail(f"BOLA view exploit succeeded! Status: {res.status_code}")

    # 5. BOLA - Unauthorized Delete
    # Bob tries to delete Alice's file (ID: 1)
    res = requests.delete(f"{BASE_URL}/api/files/1", headers=bob_headers)
    if res.status_code == 403:
        print_success("BOLA (Cross-tenant file delete) successfully blocked.")
    else:
        print_fail(f"BOLA delete exploit succeeded! Status: {res.status_code}")

    # 6. Path Traversal - Arbitrary File Read
    res = requests.get(f"{BASE_URL}/api/download?name=../server_config.txt", headers=alice_headers)
    if res.status_code == 404:
        print_success("Path Traversal (File Read) successfully contained.")
    else:
        print_fail(f"Path Traversal read succeeded! Status: {res.status_code}")

    # 7. Path Traversal - Arbitrary File Write
    res = requests.post(f"{BASE_URL}/api/files", headers=alice_headers, json={"filename": "../app.py", "content": "malicious"})
    if res.status_code == 400:
        print_success("Path Traversal (File Write) successfully contained.")
    else:
        print_fail(f"Path Traversal write succeeded! Status: {res.status_code}")

    # 8. Unauthenticated Sensitive Endpoint
    res = requests.get(f"{BASE_URL}/api/users")
    if res.status_code == 401:
        print_success("Unauthenticated access to /api/users successfully blocked.")
    else:
        print_fail(f"Unauthenticated endpoint exposure still active! Status: {res.status_code}")

    # 9. Brute-Force Rate Limiting
    print("[*] Testing Brute-Force Rate Limiter (Sending 6 rapid failed logins...)")
    for _ in range(5):
        requests.post(f"{BASE_URL}/login", json={"username": "admin", "password": "wrong"})
    
    # The 6th attempt should trigger the 429 Too Many Requests
    res = requests.post(f"{BASE_URL}/login", json={"username": "admin", "password": "wrong"})
    if res.status_code == 429:
        print_success("Brute-Force Rate Limiting successfully triggered.")
    else:
        print_fail(f"Brute-Force Rate Limiting failed! Status: {res.status_code}")

    print(f"\n{GREEN}=== ALL TESTS PASSED! THE API IS FULLY SECURED. ==={RESET}")

if __name__ == "__main__":
    try:
        run_tests()
    except requests.exceptions.ConnectionError:
        print_fail("Could not connect to the server. Is app.py running?")
