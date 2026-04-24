# RECAJS — JS Recon & Analysis Pipeline

A Python-based recon tool I built to automate the boring parts of JavaScript file analysis during bug bounty hunts. It grabs JS files from a target, rips through them for secrets and endpoints, and hands you a clean report to dig through.

I got tired of running the same six commands in a row every time I started a new target, so I wired them together into something that just works.

---

## Why This Exists

When you're doing recon, JavaScript files are basically low-hanging fruit. Dev teams leave API endpoints, tokens, cloud storage URLs, and internal paths buried in frontend bundles all the time. The problem is actually getting to them — you need subdomains, live hosts, historical URLs, crawl data, and then you still have to fetch and grep through hundreds of files manually.

This tool chains that whole process together. You point it at a domain, it runs the recon, collects the JS, and scans it for interesting stuff.

---
## Demo / Preview
<img width="555" height="634" alt="recajs_screenshot" src="https://github.com/user-attachments/assets/a71415d4-e3c6-432b-8aa8-7b2bfe7c8405" />

## Features

- Subdomain enumeration with subfinder
- Live host filtering via httpx
- Historical URL collection from Wayback Machine and GAU
- Active crawling with Katana to find JS files the archives missed
- Optional Nuclei scan for quick vulnerability checks
- JS extraction, fetching, and noise filtering (no one cares about Google Analytics)
- Regex-based secret detection (API keys, tokens, AWS creds, JWTs, etc.)
- jsecrets integration for a second pass on secrets
- Endpoint and relative path extraction from JS content
- Threaded fetching so you're not sitting around forever
- Clean summary report with everything in one place

---

## How It Works

The pipeline is split into two phases:

**Phase 1 — Recon**
1. Enumerate subdomains with subfinder
2. Probe live hosts with httpx
3. Pull historical URLs from waybackurls and gau
4. Crawl live hosts with Katana to find more endpoints
5. (Optional) Run Nuclei on live hosts for quick wins
6. Merge and dedupe everything into a single URL list

**Phase 2 — JS Analysis**
1. Extract `.js` URLs from the recon output
2. Filter out analytics and CDN noise
3. Fetch JS files concurrently
4. Run jsecrets on the combined content
5. Run regex detection for secrets, tokens, and endpoints
6. Dump everything into a summary report

---

## Installation

You need Python 3.10+ and a handful of external tools in your PATH.

**Python deps:**
```bash
pip install requests urllib3
```

**External tools (install these separately):**
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [gau](https://github.com/lc/gau)
- [katana](https://github.com/projectdiscovery/katana)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [jsecrets](https://github.com/raverrr/jsecrets) *(optional but recommended)*

Clone the repo and you're good to go:
```bash
git clone https://github.com/0xSH1N3/recajs.git
cd recajs
python jsrecon.py --check-tools
```

---

## Usage

**Full run (recon + JS analysis):**
```bash
python jsrecon.py -d example.com
```

**Skip Nuclei if you're in a hurry:**
```bash
python jsrecon.py -d example.com --skip-nuclei
```

**JS analysis only (recon already done):**
```bash
python jsrecon.py -d example.com --js-only
```

**More threads, longer timeout for big targets:**
```bash
python jsrecon.py -d example.com --threads 30 --timeout 20
```

**Include analytics/CDN JS (usually useless):**
```bash
python jsrecon.py -d example.com --no-filter-noise
```

**Check which tools are installed:**
```bash
python jsrecon.py --check-tools
```

---

## What Gets Generated

Two output directories are created:

- `example.com_recon/` — raw output from recon tools
- `example.com_jsrecon/` — JS analysis results

Key files you'll care about:

| File | What's in it |
|------|-------------|
| `js_files.txt` | All discovered JS URLs |
| `all_js_content.js` | Fetched JS files combined into one big file |
| `potential_secrets.txt` | Regex matches for keys, tokens, secrets |
| `jsecrets_all.txt` | Output from jsecrets scan |
| `extracted_urls.txt` | Endpoints and paths pulled from JS |
| `summary_report.txt` | Clean overview of everything found |

---

## Example Output

**Console output during a run:**
```
[*] Running subfinder...
[+] subfinder → 342 subdomains found
[*] Running httpx to filter live hosts...
[+] httpx → 89 live hosts found
[*] Extracted 156 unique JS URLs → js_files.txt
[*] Fetching 156 JS files with 20 threads...
[+] Fetched 142 JS files (14 failed)
[+] Regex detection → 23 unique secrets → potential_secrets.txt
  ► api_key: 8 match(es)
  ► aws_access_key: 2 match(es)
  ► generic_endpoint: 11 match(es)
  ► jwt_token: 2 match(es)
```

**Snippet from `potential_secrets.txt`:**
```
[API_KEY]  ak_live_51H8xYzL8Kq9ZpQr3sTmW7vBc
  → Source: https://api.example.com/static/bundle.js

[AWS_ACCESS_KEY]  AKIAIOSFODNN7EXAMPLE
  → Source: https://cdn.example.com/assets/app.js

[GENERIC_ENDPOINT]  https://internal-api.example.com/v2/users
  → Source: https://www.example.com/js/dashboard.js
```

**Snippet from `summary_report.txt`:**
```
  Subfinder subdomains  : 342
  Live hosts (httpx)    : 89
  JS files discovered   : 156
  JS files fetched      : 142
  Combined JS size      : 2847 KB

  api_key              : 8
  aws_access_key       : 2
  generic_endpoint     : 11
  jwt_token            : 2
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| subfinder | Subdomain enumeration |
| httpx | Live host probing |
| waybackurls | Wayback Machine URL extraction |
| gau | Alternative historical URL source |
| katana | Active web crawling |
| nuclei | Vulnerability scanning |
| jsecrets | Dedicated JS secret scanner |

---

## Limitations

- **False positives happen.** Regex secret detection will catch strings that look like tokens but aren't. Always verify findings manually.
- **Large JS bundles** (think 5MB+ minified Webpack chunks) can slow down fetching and scanning. The tool handles them, but it takes time.
- **Obfuscated JS** won't give up its secrets easily. If a dev ran everything through a heavy obfuscator, you're probably out of luck.
- **jsecrets is optional.** If you don't have it installed, the regex scanner still runs, but you miss a second opinion.
- **Rate limiting** isn't built in. If you're hammering a target with 50 threads, you might get blocked. Adjust `--threads` accordingly.

---

## Future Improvements

These are things I'd like to add when I get time:

- Slack/Discord webhook notifications for critical findings
- A simple TUI or web dashboard instead of scrolling terminal output
- Smarter noise filtering based on JS content entropy
- Integration with TruffleHog for deeper secret detection
- Auto-filtering of already-known false positives
- Support for authenticated crawling (cookies/API tokens)

---

## Disclaimer

This tool is for authorized security testing and bug bounty research only. Don't point it at systems you don't own or have explicit permission to test. The author isn't responsible for misuse.

---

## A Message from 0xSH1N3

I built this over a few weekends after getting frustrated with my own manual recon workflow. It's not perfect, but it saves me hours on every target. If you find it useful, cool. If you find bugs or have ideas, open an issue — or better yet, send Dm
🌐 Connect with Me
💼 [LinkedIn](https://www.linkedin.com/in/synxop777)  
📸 [Instagram](https://instagram.com/0xshin3)
