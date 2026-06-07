#!/usr/bin/env python3
"""
SubHunter - Passive DNS Subdomain Enumeration Tool
Combines 6 free sources + DNS brute-force for maximum coverage
Features: Source tagging, HTTP probing, manual -o output
"""
import yaml
import dns.resolver
import requests
import concurrent.futures
import argparse
import os
import sys
import socket
import http.client
from datetime import datetime

# ─── LOAD API KEYS FROM CONFIG ─────────────────────────────────────────────────
def load_config():
    local_path  = "config.yaml"
    config_path = os.path.expanduser("~/.config/subhunter/config.yaml")
    path = local_path if os.path.exists(local_path) else config_path
    if os.path.exists(path):
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
        return cfg
    return {}

cfg                = load_config()
VT_API_KEY         = cfg.get("virustotal", "")
SECURITYTRAILS_KEY = cfg.get("securitytrails", "")
ALIENVAULT_KEY     = cfg.get("alienvault", "")
HACKERTARGET_KEY   = ""
# ───────────────────────────────────────────────────────────────────────────────

THREADS     = 100
DNS_TIMEOUT = 2
HEADERS     = {"User-Agent": "SubHunter/1.0"}

def banner():
    print(r"""
  ____        _     _   _             _
 / ___| _   _| |__ | | | |_   _ _ __ | |_ ___ _ __
 \___ \| | | | '_ \| |_| | | | | '_ \| __/ _ \ '__|
  ___) | |_| | |_) |  _  | |_| | | | | ||  __/ |
 |____/ \__,_|_.__/|_| |_|\__,_|_| |_|\__\___|_|

         Multi-Source Passive DNS Recon Tool
    """)

# ─── SOURCE 1: crt.sh ──────────────────────────────────────────────────────────
def source_crtsh(domain):
    print("[*] crt.sh (Certificate Transparency)...")
    found = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, headers=HEADERS
        )
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add((name, "crt.sh"))
    except Exception as e:
        print(f"  [!] crt.sh failed: {e}")
    print(f"  [+] crt.sh: {len(found)} subdomains")
    return found

# ─── SOURCE 2: VirusTotal ──────────────────────────────────────────────────────
def source_virustotal(domain):
    if not VT_API_KEY:
        print("  [-] VirusTotal: No API key. Skipping.")
        return set()
    print("[*] VirusTotal (Passive DNS)...")
    found = set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": VT_API_KEY}
    try:
        while url:
            r = requests.get(url, headers=headers, params={"limit": 40}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", []):
                    found.add((item["id"], "VirusTotal"))
                url = data.get("links", {}).get("next")
            else:
                break
    except Exception as e:
        print(f"  [!] VirusTotal failed: {e}")
    print(f"  [+] VirusTotal: {len(found)} subdomains")
    return found

# ─── SOURCE 3: SecurityTrails ──────────────────────────────────────────────────
def source_securitytrails(domain):
    if not SECURITYTRAILS_KEY:
        print("  [-] SecurityTrails: No API key. Skipping.")
        return set()
    print("[*] SecurityTrails (Passive DNS)...")
    found = set()
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": SECURITYTRAILS_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            for sub in r.json().get("subdomains", []):
                found.add((f"{sub}.{domain}", "SecurityTrails"))
        else:
            print(f"  [!] SecurityTrails error: {r.status_code}")
    except Exception as e:
        print(f"  [!] SecurityTrails failed: {e}")
    print(f"  [+] SecurityTrails: {len(found)} subdomains")
    return found

# ─── SOURCE 4: AlienVault OTX ─────────────────────────────────────────────────
def source_alienvault(domain):
    print("[*] AlienVault OTX (Threat Intel)...")
    found = set()
    hdrs = {}
    if ALIENVAULT_KEY:
        hdrs["X-OTX-API-KEY"] = ALIENVAULT_KEY
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = requests.get(url, headers=hdrs, timeout=10)
        if r.status_code == 200:
            for entry in r.json().get("passive_dns", []):
                hostname = entry.get("hostname", "").lstrip("*.")
                if hostname.endswith(f".{domain}") or hostname == domain:
                    found.add((hostname, "AlienVault"))
    except Exception as e:
        print(f"  [!] AlienVault failed: {e}")
    print(f"  [+] AlienVault: {len(found)} subdomains")
    return found

# ─── SOURCE 5: HackerTarget ───────────────────────────────────────────────────
def source_hackertarget(domain):
    print("[*] HackerTarget...")
    found = set()
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=10, headers=HEADERS
        )
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip()
                    if sub.endswith(f".{domain}"):
                        found.add((sub, "HackerTarget"))
    except Exception as e:
        print(f"  [!] HackerTarget failed: {e}")
    print(f"  [+] HackerTarget: {len(found)} subdomains")
    return found

# ─── SOURCE 6: ThreatCrowd ────────────────────────────────────────────────────
def source_threatcrowd(domain):
    print("[*] ThreatCrowd...")
    found = set()
    try:
        r = requests.get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            timeout=10, headers=HEADERS
        )
        if r.status_code == 200:
            for sub in r.json().get("subdomains", []):
                if sub.endswith(f".{domain}"):
                    found.add((sub, "ThreatCrowd"))
    except Exception as e:
        print(f"  [!] ThreatCrowd failed: {e}")
    print(f"  [+] ThreatCrowd: {len(found)} subdomains")
    return found

# ─── SOURCE 7: DNS Brute Force ────────────────────────────────────────────────
def source_bruteforce(domain, wordlist_path):
    print(f"[*] DNS brute-force ({wordlist_path})...")
    found = set()
    try:
        with open(wordlist_path) as f:
            words = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"  [!] Wordlist not found: {wordlist_path}. Skipping.")
        return found

    def resolve(word):
        sub = f"{word}.{domain}"
        try:
            r = dns.resolver.Resolver()
            r.timeout = DNS_TIMEOUT
            r.lifetime = DNS_TIMEOUT
            r.resolve(sub, "A")
            return (sub, "BruteForce")
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for result in ex.map(resolve, words):
            if result:
                found.add(result)

    print(f"  [+] Brute-force: {len(found)} subdomains")
    return found

# ─── DNS VALIDATION ───────────────────────────────────────────────────────────
def dns_validate(subdomains_dict):
    print(f"\n[*] DNS resolving {len(subdomains_dict)} unique candidates...")

    def check(sub):
        try:
            r = dns.resolver.Resolver()
            r.timeout = DNS_TIMEOUT
            r.lifetime = DNS_TIMEOUT
            r.resolve(sub, "A")
            return sub
        except Exception:
            return None

    alive = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for result in ex.map(check, subdomains_dict.keys()):
            if result:
                alive.add(result)

    return {s: src for s, src in subdomains_dict.items() if s in alive}

# ─── MULTI-PROTOCOL PROBING ───────────────────────────────────────────────────
def probe_host(sub):
    """Try HTTPS, HTTP, then TCP. Return (port, status) or None."""
    for scheme, port in [("https", 443), ("http", 80), ("http", 8080), ("https", 8443)]:
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(sub, port, timeout=3)
            else:
                conn = http.client.HTTPConnection(sub, port, timeout=3)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            conn.close()
            return (port, str(resp.status))
        except Exception:
            pass

    # fallback: raw TCP
    for port in [80, 443, 8080, 8443]:
        try:
            sock = socket.create_connection((sub, port), timeout=2)
            sock.close()
            return (port, "TCP-open")
        except Exception:
            pass

    return None

def multi_probe(subdomains_dict):
    print(f"[*] Probing {len(subdomains_dict)} subdomains (HTTP HEAD + TCP)...")
    results = []

    def probe(item):
        sub, sources = item
        r = probe_host(sub)
        if r:
            port, status = r
            return (sub, sources, port, status)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for result in ex.map(probe, subdomains_dict.items()):
            if result:
                results.append(result)

    return sorted(results, key=lambda x: x[0])

# ─── SAVE RESULTS ─────────────────────────────────────────────────────────────
def save_results(domain, active, all_found, filename):
    with open(filename, "w") as f:
        f.write(f"SubHunter Results — {domain}\n")
        f.write(f"Scan time : {datetime.now()}\n")
        f.write(f"Candidates: {len(all_found)}\n")
        f.write(f"Live hosts: {len(active)}\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"{'SUBDOMAIN':<50} {'PORT':<8} {'STATUS':<12} SOURCES\n")
        f.write("-" * 70 + "\n")
        for sub, sources, port, status in active:
            src = ', '.join(sorted(sources))
            f.write(f"{sub:<50} :{port:<7} {status:<12} {src}\n")
        f.write("\n\nALL CANDIDATES (unvalidated)\n")
        f.write("-" * 70 + "\n")
        for sub in sorted(all_found.keys()):
            src = ', '.join(sorted(all_found[sub]))
            f.write(f"{sub}  [Source: {src}]\n")
    print(f"\n[✓] Results saved to: {filename}")

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="SubHunter — Multi-source passive DNS recon")
    parser.add_argument("domain",              help="Target domain e.g. example.com")
    parser.add_argument("-w", "--wordlist",    default="wordlist.txt", help="Wordlist for brute-force")
    parser.add_argument("-o", "--output",      default=None, help="Save output to file e.g. -o results.txt")
    parser.add_argument("--no-brute",          action="store_true", help="Skip DNS brute-force")
    parser.add_argument("--only-passive",      action="store_true", help="Passive sources only, no brute-force")
    parser.add_argument("--no-validate",       action="store_true", help="Skip DNS validation")
    parser.add_argument("--no-probe",          action="store_true", help="Skip HTTP/TCP probing")
    args = parser.parse_args()

    print(f"\n[~] Target : {args.domain}")
    print(f"[~] Output : {args.output if args.output else 'not saving (use -o filename.txt)'}\n")

    # ── Collect from all sources (returns set of (subdomain, source) tuples) ──
    all_tuples = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = [
            ex.submit(source_crtsh,          args.domain),
            ex.submit(source_virustotal,      args.domain),
            ex.submit(source_securitytrails,  args.domain),
            ex.submit(source_alienvault,      args.domain),
            ex.submit(source_hackertarget,    args.domain),
            ex.submit(source_threatcrowd,     args.domain),
        ]
        for future in concurrent.futures.as_completed(futures):
            all_tuples.update(future.result())

    if not args.no_brute and not args.only_passive:
        all_tuples.update(source_bruteforce(args.domain, args.wordlist))

    # ── Merge into dict {subdomain: {sources}} ──
    all_found = {}
    for (sub, source) in all_tuples:
        if sub not in all_found:
            all_found[sub] = set()
        all_found[sub].add(source)

    print(f"\n[~] Total unique candidates: {len(all_found)}")

    # ── DNS Validation ──
    if not args.no_validate:
        all_found = dns_validate(all_found)
        print(f"[~] DNS alive: {len(all_found)}")

    if not all_found:
        print("[!] No subdomains found.")
        sys.exit(0)

    # ── HTTP/TCP Probing ──
    if args.no_probe:
        active = [(s, src, "—", "not-probed") for s, src in sorted(all_found.items())]
    else:
        active = multi_probe(all_found)

    # ── Print Results ──
    print(f"\n{'='*70}")
    print(f"  LIVE SUBDOMAINS — {args.domain}")
    print(f"{'='*70}")
    print(f"  {'SUBDOMAIN':<48} {'PORT':<7} {'STATUS':<10} SOURCES")
    print(f"  {'-'*65}")
    for sub, sources, port, status in active:
        src = ', '.join(sorted(sources))
        print(f"  {sub:<48} :{port:<6} {status:<10} [{src}]")

    print(f"\n  Total live: {len(active)}")

    # ── Save if -o given ──
    if args.output:
        save_results(args.domain, active, all_found, args.output)
    else:
        print("\n[i] Tip: add -o results.txt to save output")

if __name__ == "__main__":
    main()
