# IOC Ranger

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" /></a>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-informational" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" />
  <a href="#features"><img src="https://github.com/user-attachments/assets/ec52832a-894d-4a64-a048-02fba92e35a1" /></a>
</p>

A fast, colorful, and extensible IOC checker for **hashes, IPs, domains, and URLs**.

- **VirusTotal**: file reputation, detections, and **code-signing** info  
- **AbuseIPDB**: IP abuse confidence, reports, last reported time  
- **IPQualityScore**: IP/Domain/URL risk, **VPN/Proxy/TOR** flags, fraud score

## Table of contents
- [Features](#features)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [Configuration](#configuration)
- [Examples](#examples)
- [Roadmap](#roadmap)
- [Social](#social)


## Features
- Interactive CLI with colorful banner (Rich)
- Auto-classify: hashes • IPs • domains • URLs
- VirusTotal (hash reputation & code-signing)
- AbuseIPDB (abuse score, last reported)
- IPQualityScore (risk + VPN/Proxy/TOR flags)
- CSV/JSON tables, simple on-disk caching
- Windows/macOS/Linux, no secrets committed (.env)


## Quickstart

### Windows (CMD)
```bat
git clone https://github.com/<you>/IOC-Ranger
cd IOC-Ranger
python -m venv .venv && call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
copy .env.example .env  &  notepad .env   :: fill keys
python -m ioc_ranger -t mixed -i inputs\iocs_mixed.txt -f table
```


### macOS/Linux
```bash
git clone https://github.com/<you>/IOC-Ranger
cd IOC-Ranger
python -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env && $EDITOR .env
python -m ioc_ranger -t mixed -i inputs/iocs_mixed.txt -f table
```


## Usage
```bash
python -m ioc_ranger --help
# Common Interactive:
python -m ioc_ranger
# Common Noninteractive:
python -m ioc_ranger -t hashes -i inputs/hashes.txt -f table csv
python -m ioc_ranger -t mixed  -i inputs/iocs_mixed.txt -o outputs/results -f table csv json
```


## Configuration
```dotenv
VT_API_KEY=...
ABUSEIPDB_API_KEY=...
IPQS_API_KEY=...
CACHE_TTL=86400
```


## Examples
- **Hashes file** → show a real snippet of output table and a link to VT GUI from CSV.
- **IPs file** → highlight AbuseIPDB score + IPQS VPN/Proxy flags.
- **Mixed file** → show how types are auto-detected.


## Roadmap
- [ ] Progress bar + ETA
- [ ] JSONL & Markdown/HTML report exports
- [ ] WHOIS + GeoIP enrichment
- [ ] Delta mode (compare runs)
- [ ] Windows EXE build (PyInstaller)
- [ ] GitHub Actions (lint/test/build)


## Social
- 📧 A.eskenazicohen@gmail.com
- 💼 [LinkedIn](https://linkedin.com/in/aaron-eskenazi-vzla)
- 🐈‍⬛ [GitHub](https://github.com/UserAaronVzla)



