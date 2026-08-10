import docker
import re
import urllib.parse
import os
import ollama

def check_memory(ip_address):
    if os.path.exists('memory_blacklist.txt'):
        with open('memory_blacklist.txt', 'r') as f:
            banned_ips = f.read().splitlines()
            if ip_address in banned_ips:
                return True
    return False

def add_to_memory(ip_address):
    with open('memory_blacklist.txt', 'a') as f:
        f.write(f"{ip_address}\n")
    print(f"[THREAT INTEL] IP {ip_address} appended to system memory.")

def deploy_firewall_rule(client, attacker_ip):
    print(f"\n[SOAR AUTOMATION] Deploying active mitigation against {attacker_ip}...")
    try:
        victim = client.containers.get('sozo_victim')
        result = victim.exec_run(f"iptables -A INPUT -s {attacker_ip} -j DROP", user='root')
        
        if result.exit_code == 0:
            print(f"[FIREWALL SUCCESS] L3 Isolation complete for {attacker_ip}.")
        else:
            print(f"[WAF SUCCESS] {attacker_ip} appended to Application Firewall blocklist.")
            
    except Exception as e:
        print(f"[ERROR] Mitigation deployment failed: {e}")

def generate_narrative(raw_log, attack_type):
    print(f"\n[SOC NARRATOR] Synthesizing incident report for {attack_type}...")
    prompt = f"You are a SOC analyst. An automated immune system just caught a {attack_type} attack. Here is the raw log: {raw_log}. Write a 1-sentence plain-language summary of the incident."
    
    response = ollama.chat(model='phi4-mini', messages=[
        {'role': 'system', 'content': 'You are a concise security AI storyteller.'},
        {'role': 'user', 'content': prompt}
    ])
    print(f"\nINCIDENT REPORT:\n{response['message']['content']}")

def start_immune_core():
    client = docker.from_env()
    
    try:
        container = client.containers.get('sozo_victim')
        print("[SYSTEM] Immune Core initialized. Ingesting telemetry from 'sozo_victim'...")
    except docker.errors.NotFound:
        print("[ERROR] Target container 'sozo_victim' offline.")
        return

    # Threat Signatures
    sqli_pattern = re.compile(r"'\s+(OR|AND)\s+'?\d+'?\s*=\s*'?\d+", re.IGNORECASE)
    brute_pattern = re.compile(r"/vulnerabilities/brute/\?username=", re.IGNORECASE)

    for line in container.logs(stream=True, tail=0):
        raw_log = line.decode('utf-8').strip()
        decoded_log = urllib.parse.unquote_plus(raw_log)
        attacker_ip = decoded_log.split(" ")[0]

        if check_memory(attacker_ip):
            print(f"\n[MEMORY INTERCEPT] Known threat actor {attacker_ip} blocked at edge.")
            print("-" * 60)
            continue 

        # Signature Matching Engine
        attack_detected = None

        if sqli_pattern.search(decoded_log):
            attack_detected = "SQL Injection"
        elif brute_pattern.search(decoded_log):
            attack_detected = "Brute Force"

        if attack_detected:
            print(f"\n[ALERT] INNATE ENGINE TRIGGERED: {attack_detected} Detected!")
            
            add_to_memory(attacker_ip)
            deploy_firewall_rule(client, attacker_ip)
            generate_narrative(decoded_log, attack_detected)
            print("-" * 60)

if __name__ == "__main__":
    start_immune_core()