# 🕵️ SPYBAR – Ultimate Cyber Assessment Suite

# ⚖️ Legal Notice

## Educational & Defensive Security Purpose Only

Spybar is an open-source cybersecurity framework created solely for:

- 📚 Learning and education
- 🛡️ Defensive security research
- 🧪 Testing in authorized lab environments
- 🎓 Ethical hacking practice
- 🔍 Security awareness and skill development

### Authorized Use Only

This project must only be used on:

- Systems you own.
- Systems you have explicit written permission to test.
- Legal Capture The Flag (CTF) platforms.
- Authorized penetration testing engagements.
- Personal laboratory environments.

### Prohibited Use

You must **NOT** use Spybar for:

- Unauthorized access to computer systems.
- Illegal hacking or intrusion.
- Data theft or privacy violations.
- Service disruption or malicious attacks.
- Any activity that violates local, national, or international laws.

### Disclaimer of Liability

The author (**Abhirup Payne**) and contributors provide this project **"AS IS"**, without any express or implied warranty.

The author is **not responsible or liable** for any misuse, damages, legal consequences, or losses resulting from the use of this software. By using Spybar, you accept full responsibility for ensuring your actions comply with all applicable laws, regulations, and ethical guidelines.

### Responsible Disclosure

If you discover a security issue within this project, please report it responsibly instead of publicly disclosing it.

---

**By downloading, using, or contributing to Spybar, you acknowledge that you have read, understood, and agreed to this Legal Notice.**
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
