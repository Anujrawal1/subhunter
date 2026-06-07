# SubHunter — Multi-Source Passive DNS Recon Tool

A Python-based subdomain enumeration tool combining 6 passive DNS
sources + DNS brute-force + HTTP probing. Results include source
tagging and live/dead filtering.

## Features
- 6 passive sources: crt.sh, VirusTotal, SecurityTrails, AlienVault, HackerTarget, ThreatCrowd
- DNS brute-force with custom wordlist
- HTTP HEAD + TCP probing (filters dead subdomains)
- Source tagging: shows which source found each subdomain
- Manual output with -o flag

## Installation
```bash
git clone https://github.com/YOUR_USERNAME/subhunter.git
cd subhunter
pip install -r requirements.txt
cp config.yaml.example config.yaml
nano config.yaml  # paste your free API keys
```

## Get Free API Keys
| Service | Free Tier | Link |
|---|---|---|
| VirusTotal | 500 req/day | https://virustotal.com |
| SecurityTrails | 50 req/month | https://securitytrails.com |
| AlienVault OTX | Unlimited | https://otx.alienvault.com |

## Usage
```bash
# Basic scan
python subdomain_hunter.py example.com

# Save results
python subdomain_hunter.py example.com -o results.txt

# Passive only (no brute-force)
python subdomain_hunter.py example.com --only-passive

# Skip HTTP probing (faster)
python subdomain_hunter.py example.com --no-probe
```

## Output Example
SUBDOMAIN                                PORT    STATUS    SOURCES
api.example.com                          :443    200       [VirusTotal, crt.sh]
mail.example.com                         :80     TCP-open  [AlienVault]
dev.example.com                          :8080   200       [BruteForce]

## Ethical Use
Only scan domains you own or have written permission to test.

## License
MIT
EOF

