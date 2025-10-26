# IOC Ranger

A fast, colorful, and extensible IOC checker for **hashes, IPs, domains, and URLs**.

- **VirusTotal**: file reputation, detections, and **code-signing** info  
- **AbuseIPDB**: IP abuse confidence, reports, last reported time  
- **IPQualityScore**: IP/Domain/URL risk, **VPN/Proxy/TOR** flags, fraud score

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

## Inputs

One IOC per line, comments starting with ```#``` or ```//``` are ignored.

```--type``` can be ```hashes | ips | domains | urls | mixed``` (auto-classify each line).

## Outputs

```--format table csv json``` (may pass multiple).

Files are written under ```--out``` (default ```outputs/results``` → ```.csv/.json```).





