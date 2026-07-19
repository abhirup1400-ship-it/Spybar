#!/usr/bin/env python3
"""
SPYBAR – Ultra‑Fast & Reliable Cyber Assessment Suite
Author: Cyber Student (Authorized Government Project)
Version: 6.0 (Stable)

Dependencies:
  pip install scapy cryptography colorama requests dnspython
"""

import os, sys, time, re, ssl, socket, random, threading, ipaddress
from getpass import getpass
from urllib.parse import urlparse, urljoin, parse_qs
from queue import Queue
from datetime import datetime

# Third‑party imports
try:
    from scapy.all import IP, TCP, sr1, RandShort, send
except ImportError:
    sys.exit("[!] 'scapy' missing. Install: pip install scapy")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    sys.exit("[!] 'cryptography' missing. Install: pip install cryptography")

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[!] 'requests' missing. Install: pip install requests")

try:
    import dns.resolver, dns.zone, dns.query, dns.rdatatype, dns.reversename
except ImportError:
    sys.exit("[!] 'dnspython' missing. Install: pip install dnspython")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except:
    class Fore: pass
    class Style: pass

# ----------------------------------------------------------------------
# Constants & Crypto
# ----------------------------------------------------------------------
MAGIC = b"SPY"
SALT_SIZE = 16; NONCE_SIZE = 12; TAG_SIZE = 16; KDF_ITERATIONS = 600_000

def derive_key(pwd, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=KDF_ITERATIONS, backend=default_backend())
    return kdf.derive(pwd.encode())

def encrypt_file(path):
    if not os.path.isfile(path): print(f"{Fore.RED}[-] File not found."); return
    pwd = getpass("[*] Encryption passphrase: ")
    if not pwd: print(f"{Fore.RED}[-] Passphrase empty."); return
    with open(path, "rb") as f: pt = f.read()
    salt = os.urandom(SALT_SIZE); key = derive_key(pwd, salt); nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key); ct = aesgcm.encrypt(nonce, pt, None)
    out = path + ".spy"
    with open(out, "wb") as f: f.write(MAGIC + salt + nonce + ct)
    print(f"{Fore.GREEN}[+] Encrypted -> {out}")
    if input("[?] Delete original? (y/N): ").lower() == "y":
        os.remove(path); print(f"{Fore.YELLOW}[i] Original deleted.")

def decrypt_file(path):
    if not os.path.isfile(path): print(f"{Fore.RED}[-] Vault not found."); return
    with open(path, "rb") as f: data = f.read()
    if len(data) < len(MAGIC)+SALT_SIZE+NONCE_SIZE+TAG_SIZE or data[:len(MAGIC)] != MAGIC:
        print(f"{Fore.RED}[-] Invalid SPYBAR vault."); return
    salt = data[len(MAGIC):len(MAGIC)+SALT_SIZE]
    nonce = data[len(MAGIC)+SALT_SIZE:len(MAGIC)+SALT_SIZE+NONCE_SIZE]
    ct = data[len(MAGIC)+SALT_SIZE+NONCE_SIZE:]
    pwd = getpass("[*] Decryption passphrase: ")
    key = derive_key(pwd, salt); aesgcm = AESGCM(key)
    try: pt = aesgcm.decrypt(nonce, ct, None)
    except: print(f"{Fore.RED}[-] Wrong password or tampered."); return
    out = path[:-4] if path.endswith(".spy") else path + ".dec"
    with open(out, "wb") as f: f.write(pt)
    print(f"{Fore.GREEN}[+] Decrypted -> {out}")

# ----------------------------------------------------------------------
# SYN Scanner
# ----------------------------------------------------------------------
def syn_scan(target_ip, ports, timeout=1.0):
    open_ports = []
    total = len(ports)
    for idx, port in enumerate(ports, 1):
        print(f"\r[*] SYN scanning {port}/{ports[-1]} ({idx}/{total})", end="", flush=True)
        try:
            resp = sr1(IP(dst=target_ip)/TCP(dport=port, sport=RandShort(), flags="S"),
                       timeout=timeout, verbose=0)
            if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                open_ports.append(port)
                send(IP(dst=target_ip)/TCP(dport=port, sport=resp[TCP].sport, flags="R"), verbose=0)
        except PermissionError:
            print(f"\n{Fore.RED}[-] Root required."); return []
        except: pass
    print()
    return open_ports

def syn_scanner_menu():
    if os.geteuid() != 0:
        print(f"{Fore.RED}[-] Root required."); return
    target = input("[*] Target IP/domain: ").strip()
    if not target: return
    try: ipaddress.ip_address(target)
    except ValueError:
        try: target = socket.gethostbyname(target); print(f"{Fore.GREEN}[+] Resolved -> {target}")
        except: print(f"{Fore.RED}[-] Invalid host."); return
    print("\n[1] Top 100 common ports (fast)")
    print("[2] Top 1000 ports (may take a few minutes)")
    print("[3] Custom range")
    choice = input("Profile: ").strip()
    if choice == '1':
        ports = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,8080,8443,5900,20,1433,1521]
    elif choice == '2':
        ports = list(range(1, 1025))
    elif choice == '3':
        try:
            s = int(input("Start: ")); e = int(input("End: "))
            ports = list(range(s, e+1))
        except: print("Invalid range."); return
    else: return
    print(f"\n[*] Scanning {target} with {len(ports)} ports...")
    open_ports = syn_scan(target, ports)
    if open_ports:
        print(f"{Fore.GREEN}[+] Open ports: {', '.join(map(str, open_ports))}")
    else:
        print(f"{Fore.YELLOW}[i] No open ports found.")

# ----------------------------------------------------------------------
# OWASP Top 10 Scanner – FULLY FIXED & ACCURATE
# ----------------------------------------------------------------------
class OWASPScanner:
    CVE_MAP = {
        "Apache/2.2": "CVE-2011-3192 (Range header DoS), multiple RCE",
        "Apache/2.4.49": "CVE-2021-41773 (Path traversal, RCE)",
        "PHP/5": "CVE-2018-19395 (Buffer overflow), many EOL",
        "PHP/7.0": "EOL, multiple CVEs",
        "IIS/6": "CVE-2017-7269 (WebDAV RCE)",
        "IIS/7": "Several RCE vulnerabilities",
        "OpenSSL/1.0": "CVE-2014-0160 (Heartbleed)",
        "nginx/0.": "EOL, multiple vulnerabilities",
    }
    SENSITIVE_PATHS = [
        "robots.txt", ".git/HEAD", ".env", "backup.zip", "admin/", "wp-admin/",
        ".htaccess", "config.php.bak", "phpinfo.php", "server-status", ".DS_Store",
        "console/", "debug/", "test/", ".svn/entries", "web.config", "wp-config.php.bak",
        "dump.sql", "backup.sql", "admin/login", "administrator/", "user/login", "cpanel",
        "webmail/", "phpMyAdmin/", "mysql/", "db/", "logs/", "tmp/", "temp/"
    ]
    SQLI_ERROR_PATTERNS = [
        r"SQL syntax", r"MySQL", r"MariaDB", r"Oracle", r"PostgreSQL",
        r"unclosed quotation mark", r"Microsoft OLE DB", r"ODBC Driver",
        r"SQLite", r"DB2", r"SYNTAX ERROR", r"Warning.*mysql_"
    ]
    DEFAULT_CREDS = [
        ("admin","admin"), ("admin","password"), ("admin","123456"),
        ("admin","admin123"), ("root","root"), ("user","user"),
        ("admin","pass"), ("administrator","administrator")
    ]

    def __init__(self, target_url, cookies=None, timeout=8, threads=15):
        self.base_url = target_url.rstrip("/")
        self.parsed = urlparse(self.base_url)
        if not self.parsed.scheme:
            self.base_url = "http://" + self.base_url
            self.parsed = urlparse(self.base_url)
        self.host = self.parsed.hostname
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.scheme = self.parsed.scheme
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = timeout
        if cookies:
            for c in cookies.split(";"):
                if "=" in c: k,v = c.split("=",1); self.session.cookies.set(k.strip(), v.strip())
        self.threads = threads
        self.findings = []  # (severity, category, description)

    def _add(self, sev, cat, msg):
        col = {"HIGH":Fore.RED, "MEDIUM":Fore.YELLOW, "LOW":Fore.CYAN, "INFO":Fore.WHITE}.get(sev, Fore.WHITE)
        print(f"{col}[!] [{sev}] {cat}: {msg}{Style.RESET_ALL}")
        self.findings.append((sev, cat, msg))

    def check_ssl(self):
        if self.scheme != "https":
            self._add("MEDIUM", "A02 Crypto Failures", "Site uses HTTP (no encryption).")
            return
        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=self.host)
            conn.settimeout(5)
            conn.connect((self.host, self.port))
            cert = conn.getpeercert()
            exp_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            if exp_date < datetime.now():
                self._add("HIGH", "A02 Crypto Failures", "SSL certificate has expired!")
            cipher, proto, _ = conn.cipher()
            if cipher in ("RC4-MD5", "RC4-SHA", "DES-CBC3-SHA"):
                self._add("HIGH", "A02 Crypto Failures", f"Weak cipher used: {cipher}")
            conn.close()
        except Exception as e:
            self._add("HIGH", "A02 Crypto Failures", f"SSL handshake failed: {e}")

    def check_headers(self):
        try:
            r = self.session.get(self.base_url)
            headers = r.headers
            missing = []
            if "X-Content-Type-Options" not in headers: missing.append("X-Content-Type-Options")
            if "X-Frame-Options" not in headers: missing.append("X-Frame-Options (clickjacking)")
            if "Content-Security-Policy" not in headers: missing.append("Content-Security-Policy")
            if "Strict-Transport-Security" not in headers and self.scheme == "https": missing.append("HSTS")
            if missing:
                self._add("MEDIUM", "A05 Security Misconfiguration", f"Missing security headers: {', '.join(missing)}")
            server = headers.get("Server", "")
            if server:
                self._add("INFO", "A05 Misconfiguration", f"Server banner: {server}")
                for soft, cve in self.CVE_MAP.items():
                    if soft in server:
                        self._add("HIGH", "A06 Vulnerable Components", f"Outdated: {soft} -> {cve}")
        except requests.RequestException as e:
            self._add("HIGH", "A01/A05 Connection", f"Could not fetch homepage: {e}")

    def check_sensitive_files(self):
        q = Queue()
        for p in self.SENSITIVE_PATHS: q.put(p)
        found = []
        def worker():
            while not q.empty():
                path = q.get()
                url = urljoin(self.base_url, path)
                try:
                    r = self.session.head(url, allow_redirects=False, timeout=3)
                    if r.status_code == 200:
                        if "text/html" in r.headers.get("Content-Type", ""):
                            r2 = self.session.get(url, timeout=3)
                            if "Index of /" in r2.text:
                                found.append((path, "DIR_LISTING"))
                                q.task_done()
                                continue
                        found.append((path, "EXPOSED"))
                except: pass
                q.task_done()
        threads = []
        for _ in range(min(self.threads, len(self.SENSITIVE_PATHS))):
            t = threading.Thread(target=worker, daemon=True); t.start(); threads.append(t)
        q.join()
        for p, typ in found:
            if typ == "DIR_LISTING":
                self._add("HIGH", "A01 Broken Access Control", f"Directory listing enabled at {p}")
            else:
                self._add("MEDIUM", "A01 Broken Access Control", f"Exposed sensitive resource: {p}")
        if not found:
            print(f"{Fore.GREEN}[+] No sensitive files found.")

    def injection_tests(self):
        try:
            r = self.session.get(self.base_url)
            html = r.text
        except:
            print(f"{Fore.YELLOW}[i] Could not download homepage for injection tests.")
            return
        forms = re.findall(r'<form.*?action=["\'](.*?)["\'].*?>(.*?)</form>', html, re.DOTALL | re.I)
        if not forms:
            print(f"{Fore.YELLOW}[i] No forms detected on homepage.")
        else:
            print(f"[*] Testing {len(forms)} form(s) for injection...")
        for action, body in forms:
            action_url = urljoin(self.base_url, action) if action else self.base_url
            inputs = re.findall(r'<input[^>]+name=["\'](.*?)["\']', body, re.I)
            if not inputs: continue
            data = {name: "test" for name in inputs}
            sqli_payloads = ["'", "\"", "1' OR '1'='1", "' OR 1=1--", "' OR 'a'='a"]
            for payload in sqli_payloads:
                test_data = data.copy()
                first_key = list(test_data.keys())[0]
                test_data[first_key] = payload
                try:
                    res = self.session.post(action_url, data=test_data, allow_redirects=False, timeout=6)
                    if res.status_code == 200:
                        for pattern in self.SQLI_ERROR_PATTERNS:
                            if re.search(pattern, res.text, re.I):
                                self._add("HIGH", "A03 SQL Injection", f"Error‑based SQLi in {action_url} param '{first_key}'")
                                break
                except: pass
            xss_payload = "<script>alert('XSS')</script>"
            test_data = data.copy()
            first_key = list(test_data.keys())[0]
            test_data[first_key] = xss_payload
            try:
                res = self.session.post(action_url, data=test_data, timeout=6)
                if xss_payload in res.text:
                    self._add("HIGH", "A03 XSS", f"Reflected XSS in {action_url} param '{first_key}'")
            except: pass
        for link in re.findall(r'href=["\'](.*?)["\']', html):
            if '?' in link:
                base, qs = link.split('?', 1)
                for param in parse_qs(qs).keys():
                    test_url = urljoin(self.base_url, f"{base}?{param}=;id")
                    try:
                        res = self.session.get(test_url, timeout=6)
                        if "uid=" in res.text or "gid=" in res.text:
                            self._add("HIGH", "A03 Command Injection", f"Possible command injection in {link} param '{param}'")
                    except: pass

    def check_default_creds(self):
        login_paths = ["admin/login", "login", "wp-login.php", "user/login", "cpanel", "administrator/index.php"]
        found_any = False
        for lp in login_paths:
            url = urljoin(self.base_url, lp)
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200 and ("password" in r.text.lower() or "login" in r.text.lower()):
                    for username, password in self.DEFAULT_CREDS:
                        data = {"username": username, "password": password, "submit": "Login",
                                "log": username, "pwd": password, "user": username, "pass": password}
                        try:
                            res = self.session.post(url, data=data, timeout=6)
                            if res.status_code == 200 and ("logout" in res.text.lower() or "dashboard" in res.text.lower()):
                                self._add("HIGH", "A07 Identification Failures", f"Default credentials work at {url} ({username}:{password})")
                                found_any = True
                                break
                        except: pass
            except: pass
        if not found_any:
            print(f"{Fore.GREEN}[+] No default credentials detected on common login pages.")

    def run(self):
        print(f"\n{Fore.CYAN}[*] Starting OWASP Top 10 Scan on {self.base_url}{Style.RESET_ALL}")
        print("-" * 60)
        self.check_ssl()
        self.check_headers()
        self.check_sensitive_files()
        self.injection_tests()
        self.check_default_creds()
        print("-" * 60)
        high = sum(1 for s,_,_ in self.findings if s == "HIGH")
        med = sum(1 for s,_,_ in self.findings if s == "MEDIUM")
        if self.findings:
            print(f"\n{Fore.RED}[!] {high} HIGH, {Fore.YELLOW}{med} MEDIUM vulnerabilities found.")
        else:
            print(f"\n{Fore.GREEN}[+] No vulnerabilities found. The site appears secure based on quick OWASP checks.")
        print(f"{Fore.CYAN}[*] Always perform manual verification for a complete assessment.")

# ----------------------------------------------------------------------
# Service Detection
# ----------------------------------------------------------------------
def detect_services(target_ip, open_ports, timeout=1.5):
    print(f"\n[*] Service detection on {target_ip}...")
    services = {}
    for port in open_ports:
        print(f"\r[*] Probing port {port}  ", end="", flush=True)
        banner = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, port))
            if port == 443:
                context = ssl.create_default_context(); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target_ip)
            if port in [80,443,8080]: sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = b""
            while True:
                try:
                    data = sock.recv(1024)
                    if not data: break
                    banner += data
                    if len(banner) > 2048: break
                except: break
            sock.close()
        except: pass
        if banner:
            text = banner.decode('utf-8', errors='ignore').split('\n')[0][:100]
            if "SSH" in text: svc = "SSH"
            elif "FTP" in text or port==21: svc = "FTP"
            elif "HTTP" in text or "Server:" in text: svc = "HTTP"
            else: svc = "generic"
            services[port] = (svc, text)
            print(f"\r{Fore.GREEN}[+] Port {port}: {svc} – {text}")
        else:
            print(f"\r{Fore.YELLOW}[i] Port {port}: no banner")
    return services

# ----------------------------------------------------------------------
# OS Detection
# ----------------------------------------------------------------------
def os_detect(target_ip, open_ports):
    if not open_ports: return "Unknown"
    probe_port = open_ports[0]
    resp = sr1(IP(dst=target_ip)/TCP(dport=probe_port, sport=RandShort(), flags="S"), timeout=2, verbose=0)
    if resp and resp.haslayer(TCP):
        ttl = resp[IP].ttl
        guess = "Linux/Unix" if ttl <= 64 else "Windows" if ttl <= 128 else "Unknown"
        print(f"\n{Fore.GREEN}[+] OS guess: {guess} (TTL={ttl})")
        return guess
    print(f"\n{Fore.YELLOW}[i] OS detection failed.")
    return "Unknown"

# ----------------------------------------------------------------------
# Quick Vulnerability Checks
# ----------------------------------------------------------------------
def vuln_checks(target_ip, services):
    print(f"\n[*] Running quick vulnerability checks...")
    for port, (svc, banner) in services.items():
        if svc == "FTP" and port==21:
            try:
                sock = socket.socket(); sock.settimeout(2); sock.connect((target_ip,21))
                sock.recv(1024); sock.send(b"USER anonymous\r\n"); resp = sock.recv(1024)
                if b"331" in resp:
                    sock.send(b"PASS anonymous\r\n"); resp2 = sock.recv(1024)
                    if b"230" in resp2: print(f"{Fore.RED}[!] [HIGH] FTP anonymous login allowed")
                sock.close()
            except: pass
        if svc == "HTTP":
            for path in [".env", "admin/"]:
                try:
                    r = requests.get(f"http://{target_ip}:{port}/{path}", timeout=3, verify=False)
                    if r.status_code == 200: print(f"{Fore.RED}[!] [HIGH] Exposed {path} on HTTP {port}")
                except: pass

# ----------------------------------------------------------------------
# Fast DNS Recon
# ----------------------------------------------------------------------
class FastDNS:
    SUBDOMAINS = [
        "www","mail","ftp","webmail","smtp","pop","ns1","ns2","admin","test","portal","blog","shop",
        "api","dev","staging","m","mobile","secure","server","cdn","vpn","dns","remote","demo",
        "docs","support","status","git","deploy","jenkins","ci","monitor","grafana","kibana",
        "log","db","mysql","mariadb","oracle","redis","memcached","mongo","elastic","ldap",
        "kerberos","vault","jira","confluence","wiki","gitlab","bitbucket","mailman","lists",
        "meet","chat","irc","voip","sip","proxy","fw","firewall","ids","waf","lb","cluster",
        "node","worker","queue","cron","tasks","backup","sandbox","uat","qa","perf","load",
        "canary","partner","reseller","client","customer","app","apps","static","assets","media",
        "images","img","css","js","fonts","files","download","upload","tmp","cache","logs",
        "analytics","tracking","ad","ads","news","newsletter","press","about","contact","help",
        "faq","legal","privacy","terms","security","bug","cve","advisory","alert","health",
        "ping","healthcheck","echo","whois","dnssec","dkim","spf","dmarc","autodiscover",
        "autoconfig","lync","skype","teams","zoom","slack","discord","telegram","bot",
        "webhook","oauth","sso","saml","openid","auth","login","signin","register","signup",
        "account","profile","user","users","admin","administrator","root","dashboard","panel",
        "cp","cpanel","plesk","webmin","directadmin","cloud","host","ns3","ns4","relay",
        "gateway","mx1","mx2","imap","pop3","smtp2","roundcube","horde","webdisk","webftp",
        "ftp2","telnet","ssh","rdp","vnc","console","terminal","shell","powershell","docker",
        "kubernetes","k8s","swarm","consul","etcd","zookeeper","kafka","rabbitmq","activemq",
        "nats","mosquitto","mqtt","websocket","stream","live","vod","radio","tv","camera",
        "video","audio","podcast","rss","soap","rest","graphql","grpc","thrift","swagger",
        "openapi","prometheus","statsd","graphite","influxdb","jaeger","zipkin","trace"
    ]
    def __init__(self, domain, threads=30):
        self.domain = domain.rstrip('.')
        self.threads = threads
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1.5; self.resolver.lifetime = 2
        self.found = []

    def dns_records(self):
        print(f"\n[*] DNS records for {self.domain}")
        for rtype in ('A','NS','MX','SOA','TXT'):
            try:
                ans = self.resolver.resolve(self.domain, rtype)
                for a in ans: print(f"  {rtype:5}: {a}")
            except dns.resolver.NoAnswer: print(f"  {rtype:5}: No Answer")
            except dns.resolver.NXDOMAIN: print(f"  {rtype:5}: Domain not found")
            except Exception as e: print(f"  {rtype:5}: lookup failed ({e})")

    def subdomain_bruteforce(self):
        print(f"\n[*] Subdomain brute (200 names, {self.threads} threads)...")
        q = Queue()
        for sub in self.SUBDOMAINS: q.put(sub)
        lock = threading.Lock()
        def worker():
            while not q.empty():
                sub = q.get()
                fqdn = f"{sub}.{self.domain}"
                try:
                    ips = [str(r) for r in self.resolver.resolve(fqdn, 'A')]
                    with lock:
                        self.found.append((fqdn, ips))
                        print(f"{Fore.GREEN}[+] {fqdn} -> {', '.join(ips)}")
                except: pass
                q.task_done()
        for _ in range(self.threads): threading.Thread(target=worker, daemon=True).start()
        q.join()
        if not self.found:
            print(f"{Fore.YELLOW}[i] No subdomains discovered.")

    def whois(self):
        print(f"\n[*] WHOIS lookup...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(5)
            s.connect(("whois.iana.org", 43)); s.send(f"{self.domain}\r\n".encode())
            data = s.recv(4096).decode(errors='ignore'); s.close()
            ref = re.search(r'refer:\s*(.*)', data)
            if ref:
                whois_server = ref.group(1).strip()
                s2 = socket.socket(); s2.settimeout(5); s2.connect((whois_server, 43))
                s2.send(f"{self.domain}\r\n".encode()); info = s2.recv(4096).decode(errors='ignore'); s2.close()
                for line in info.splitlines():
                    if any(k in line.lower() for k in ['registrar','creation','expir','name server']):
                        print(f"  {line.strip()}")
            else:
                print(f"{Fore.YELLOW}[i] Could not find WHOIS server.")
        except Exception as e:
            print(f"{Fore.RED}[-] WHOIS failed: {e}")

    def run(self):
        self.dns_records()
        self.subdomain_bruteforce()
        self.whois()

# ----------------------------------------------------------------------
# Full Assessment
# ----------------------------------------------------------------------
def full_assessment():
    if os.geteuid() != 0:
        print(f"{Fore.RED}[-] Root required for SYN + OS detection."); return
    target = input("[*] Target IP or domain: ").strip()
    if not target: return
    try: ipaddress.ip_address(target)
    except ValueError:
        try: target = socket.gethostbyname(target); print(f"{Fore.GREEN}[+] Resolved -> {target}")
        except: print("Invalid."); return
    ports = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,8080,8443,5900,1433,1521]
    print(f"\n[*] Scanning top {len(ports)} ports...")
    open_ports = syn_scan(target, ports)
    if open_ports:
        services = detect_services(target, open_ports)
        os_detect(target, open_ports)
        vuln_checks(target, services)
    else:
        print(f"{Fore.YELLOW}[i] No open ports found.")
    print(f"\n{Fore.GREEN}[+] SPYBAR assessment complete.")

# ----------------------------------------------------------------------
# Banner & Main Menu
# ----------------------------------------------------------------------
def banner():
    print(f"""
{Fore.CYAN}   ▄████████  ▄██████▄     ▄█   ▄█▄ ▀█████████▄     ▄████████    ▄████████ 
  ███    ███ ███    ███   ███ ▄███▀   ███    ███   ███    ███   ███    ███ 
  ███    █▀  ███    ███   ███▐██▀     ███    ███   ███    █▀    ███    █▀  
  ███        ███    ███  ▄█████▀     ▄███▄▄▄██▀   ▄███▄▄▄      ▄███▄▄▄     
▀███████████ ███    ███ ▀▀█████▄    ▀▀███▀▀▀██▄  ▀▀███▀▀▀     ▀▀███▀▀▀     
         ███ ███    ███   ███▐██▄     ███    ██▄   ███    █▄    ███    █▄  
   ▄█    ███ ███    ███   ███ ▀███▄   ███    ███   ███    ███   ███    ███ 
 ▄████████▀   ▀██████▀    ███   ▀█▀ ▄█████████▀    ██████████   ██████████ 
                         ▀                                                
{Style.RESET_ALL}
{Fore.MAGENTA}        [ Crypto Vault | Stealth SYN | OWASP | DNS | Full Assessment ]
{Style.RESET_ALL}
""")

def main():
    banner()
    print(f"{Fore.YELLOW}[!] Use only on authorised systems.\n")
    while True:
        print(f"\n{Fore.CYAN}{'='*45}")
        print("     🔥 SPYBAR COMMAND CENTER 🔥")
        print(f"{'='*45}{Style.RESET_ALL}")
        print("1. Encrypt File")
        print("2. Decrypt File")
        print("3. Stealth SYN Port Scanner (root)")
        print("4. OWASP Top 10 Vulnerability Scanner")
        print("5. DNS Recon (records, subdomains, WHOIS)")
        print("6. Full Assessment (Ports + Service + OS + Vuln)")
        print("7. Help")
        print("8. Exit")
        ch = input("[?] Select: ").strip()
        if ch == '1': encrypt_file(input("File: ").strip())
        elif ch == '2': decrypt_file(input("Vault (.spy): ").strip())
        elif ch == '3': syn_scanner_menu()
        elif ch == '4':
            url = input("[*] Target URL (http/https): ").strip()
            if not url: continue
            cookies = input("[*] Cookies (optional, key=value;...): ").strip() or None
            th = input("[*] Threads (default 15): ").strip()
            th = int(th) if th.isdigit() else 15
            scanner = OWASPScanner(url, cookies=cookies, threads=th)
            scanner.run()
        elif ch == '5':
            dom = input("[*] Domain: ").strip()
            if dom: FastDNS(dom).run()
        elif ch == '6': full_assessment()
        elif ch == '7':
            print(f"\n{Fore.CYAN}SPYBAR Manual:\n"
                  "1-2: Crypto vault (AES‑256‑GCM)\n"
                  "3: SYN scan (root), top 100/1000/custom\n"
                  "4: OWASP Top 10 scanner (SSL, headers, sensitive files, SQLi, XSS, default creds)\n"
                  "5: DNS records, subdomain brute, WHOIS\n"
                  "6: All‑in‑one assessment\n"
                  "Always have written permission!")
        elif ch == '8': print("Exiting."); break
        else: print(f"{Fore.RED}[-] Invalid option.")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n{Fore.YELLOW}[!] Interrupted.")