<p align="center">
  <img src="https://raw.githubusercontent.com/Dannz1337/Deep-Reaver/main/assets/logo.png" width="300"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Python-blue"/>
  <img src="https://img.shields.io/badge/license-MIT-green"/>
  <img src="https://img.shields.io/github/stars/Dannz1337/Deep-Reaver?style=social"/>
</p>

# Deep Reaver

**Deep Reaver** is a powerful, AI-enhanced vulnerability assessment and exploitation toolkit built in Python.  
Inspired by tools like Nmap and Nessus, Deep Reaver is designed for deep, modular scanning of web applications and services.

---

## Features

- AI-assisted analysis via `ai_assistant.py`
- Modular vulnerability scanning:
  - [x] SQL Injection (SQLi)
  - [x] Cross-site Scripting (XSS)
  - [x] Remote Code Execution (RCE)
  - [x] Cross-Site Request Forgery (CSRF)
  - [x] File Upload Testing
  - [x] Brute Force Login Detection
  - [x] Auth Bypass & Host Header Injection
  - [x] CMS Detection & CVE Check
  - [x] LFI/RFI, XXE, CORS, JSONP, Clickjacking, SSRF, and more
- Interactive CLI with colored output, tabulated results, and progress bars
- Auto-reporting to file

---

## Installation

```bash
git clone https://github.com/Dannz1337/Deep-Reaver.git
cd Deep-Reaver/user
pip install -r requirements.txt