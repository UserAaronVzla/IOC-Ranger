# IOC Ranger

A fast, colorful, and extensible IOC checker for **hashes, IPs, domains, and URLs**.

- **VirusTotal**: file reputation, detections, and **code-signing** info  
- **AbuseIPDB**: IP abuse confidence, reports, last reported time  
- **IPQualityScore**: IP/Domain/URL risk, **VPN/Proxy/TOR** flags, fraud score

<img width="1092" height="937" alt="image" src="https://github.com/user-attachments/assets/ec52832a-894d-4a64-a048-02fba92e35a1" />


## Quickstart

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env   # add your keys

python -m ioc_ranger \
  --type mixed \
  --input inputs/iocs_mixed.txt \
  --out outputs/results \
  --format table csv json
```

# Inputs

One IOC per line, comments starting with ```#``` or ```//``` are ignored.

```--type``` can be ```hashes | ips | domains | urls | mixed``` (auto-classify each line).

# Outputs

```--format table csv json``` (may pass multiple).

Files are written under ```--out``` (default ```outputs/results``` → ```.csv/.json```).

## Windows quick start (CMD)
Install ```Python 3.10+``` (adds "```py```" and "```python```" to PATH).

- Then: ```cd ioc-ranger```

Create & activate a virtual env:

- ```python -m venv .venv```

- ```call .venv\Scripts\activate.bat```


Install dependencies:

- ```python -m pip install --upgrade pip```

- ```python -m pip install -r requirements.txt```


Add the API keys:

- Edit ```.env``` and set: ```VT_API_KEY```, ```ABUSEIPDB_API_KEY```, ```IPQS_API_KEY```


(Optional) Make sure folders exist on first run:

- ```mkdir outputs 2>nul```

- ```mkdir data 2>nul```


Run it:

- interactive → ```python -m ioc_ranger```
- non-interactive → ```python -m ioc_ranger --type mixed --input inputs\iocs_mixed.txt --out outputs\results --format table csv json```

Need help?

- ```python -m ioc_ranger --help```

