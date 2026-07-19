# 🕵️ SPYBAR – Ultimate Cyber Assessment Suite

**SPYBAR** is an all-in-one offensive security tool built for authorized penetration testing. It combines:
- 🔐 **AES‑256‑GCM file encryption/decryption**
- 🌐 **Stealth TCP SYN port scanner** (with firewall evasion)
- 🧪 **OWASP Top 10 vulnerability scanner** (SQLi, XSS, SSL, default creds)
- 🌍 **Advanced DNS reconnaissance** (WHOIS, subdomain brute, zone transfer)
- 🧬 **Service & OS detection**
- ⚡ **Automated vulnerability scripts**

## ⚙️ Installation (Kali Linux / Debian)
```bash
git clone https://github.com/YOUR_USERNAME/spybar.git
cd spybar
chmod +x install.sh
sudo apt install dos2unix
dos2unix install.sh 
./install.sh
sudo python3 spybar.py
