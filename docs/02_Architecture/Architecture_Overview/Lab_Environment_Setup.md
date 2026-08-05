The Sozo testing environment is an isolated, containerized lab designed to simulate real-world cyber attacks against a vulnerable target application without external network risks.
- **Network Name:** `sozo_internal`
- **Driver:** `bridge`
- **Subnet:** `172.28.0.0/16`
- **Scope:** Local internal container communications only. Internet egress is restricted.
**Container Name:** `sozo-victim-dvwa`
- **Image:** `vulnerables/web-dvwa:latest`
- **IP Address:** `172.28.0.10`
- **Exposed Ports:** `80:80`
- **Role:** Target web application providing HTTP access logs to the Sozo Collector.
**Container Name:** `sozo-attacker-kali`
- **Image:** `kalilinux/kali-rolling:latest`
- **IP Address:** `172.28.0.20`
- **Tools Installed:** `curl`, `nmap`, `sqlmap`, `nikto`, `hydra`
- **Role:** Generates attack payloads and benign web traffic targeting the victim.
**Container Name:** `sozo-core-engine`
- **Base Image:** `python:3.11-slim`
- **IP Address:** `172.28.0.30`
- **Role:** Mounts victim log streams, executes real-time parsing, rule evaluation, ML scoring, and SOAR lifecycle actions.
```bash
docker network create --subnet=172.28.0.0/16 sozo_internal
docker run -d --name sozo-victim-dvwa --net sozo_internal --ip 172.28.0.10 -p 80:80 vulnerables/web-dvwa
docker run -d --name sozo-attacker-kali --net sozo_internal --ip 172.28.0.20 kalilinux/kali-rolling tail -f /dev/null
docker stop sozo-victim-dvwa sozo-attacker-kali
docker rm sozo-victim-dvwa sozo-attacker-kali
docker network rm sozo_internal
