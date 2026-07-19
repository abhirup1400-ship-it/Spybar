#!/bin/bash
echo "[*] Installing SPYBAR dependencies..."
sudo apt update -y
sudo apt install python3-pip -y
pip3 install -r requirements.txt
echo "[+] Done. Run with: sudo python3 spybar.py"