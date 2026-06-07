# SubHunter — Multi-Source Passive DNS Recon Tool

A Python-based subdomain enumeration tool combining passive DNS
sources + DNS brute-force + HTTP probing. Outputs only live,
reachable targets with source tagging.

## Features
- 12 passive DNS sources combined
- DNS brute-force with custom wordlist
- HTTP HEAD + TCP probing (filters dead subdomains)
- Source tagging — shows which source found each subdomain
- Manual output with -o flag (you control when to save)
- Config file for API keys — your keys never touch the code

## Installation
```bash
git clone https://github.com/YOUR_USERNAME/subhunter.git
cd subhunter
pip install -r requirements.txt
cp config.yaml.example config.yaml
nano config.yaml
```

## API Keys — Free Sources

| # | Source | Free Tier | Key Needed | Sign Up |
|---|---|---|---|---|
| 1 | VirusTotal | 500 req/day | Yes | https://virustotal.com |
| 2 | SecurityTrails | 50 req/month | Yes | https://securitytrails.com |
| 3 | AlienVault OTX | Unlimited | Optional | https://otx.alienvault.com |
| 4 | Shodan | 100 req/month | Yes | https://shodan.io |
| 5 | Censys | 250 req/month | Yes | https://censys.io |
| 6 | BinaryEdge | 250 req/month | Yes | https://binaryedge.io |
| 7 | FullHunt | 10 req/day | Yes | https://fullhunt.io |
| 8 | Chaos | Free researchers | Yes | https://chaos.projectdiscovery.io |
| 9 | URLScan.io | 1500 req/day | Yes | https://urlscan.io |
| 10 | crt.sh | Unlimited | No | Auto-used |
| 11 | HackerTarget | Limited | No | Auto-used |
| 12 | ThreatCrowd | Unlimited | No | Auto-used |

## Usage
```bash
# Basic scan
python subdomain_hunter.py example.com

# Save results to your own file
python subdomain_hunter.py example.com -o results.txt

# Passive sources only, no brute-force
python subdomain_hunter.py example.com --only-passive -o out.txt

# Skip HTTP probing (faster)
python subdomain_hunter.py example.com --no-probe

# Skip DNS validation
python subdomain_hunter.py example.com --no-validate
```

## Output Example
======================================================================
LIVE SUBDOMAINS — example.com
SUBDOMAIN                                PORT    STATUS    SOURCES
api.example.com                          :443    200       [VirusTotal, crt.sh]
auth.example.com                         :443    301       [SecurityTrails]
dev.example.com                          :8080   200       [BruteForce]
mail.example.com                         :80     TCP-open  [AlienVault, crt.sh]
Total live: 4

## Ethical Use
Only run this tool against domains you own or have explicit
written permission to test. Unauthorized scanning may violate
laws including the Computer Fraud and Abuse Act (CFAA).

## License
MIT
