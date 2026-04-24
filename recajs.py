#!/usr/bin/env python3
"""
jsrecon.py - JS Recon & Secret Hunter | Bug Bounty Reconnaissance Tool
Single-file edition.

Usage:
    python jsrecon.py -d example.com
    python jsrecon.py -d example.com --skip-nuclei
    python jsrecon.py -d example.com --skip-recon
    python jsrecon.py -d example.com --js-only --threads 30
    python jsrecon.py -d example.com --no-filter-noise --timeout 20
    python jsrecon.py -d example.com --check-tools

Requirements:
    pip install requests urllib3

External tools (must be in PATH):
    subfinder, httpx, waybackurls, gau, katana, nuclei, jsecrets
"""

# ══════════════════════════════════════════════════════════════════════════════
#  IMPORTS
# ══════════════════════════════════════════════════════════════════════════════

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ══════════════════════════════════════════════════════════════════════════════
#  UTILS — Colors, Logging, File Helpers, Subprocess
# ══════════════════════════════════════════════════════════════════════════════

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    GRAY    = "\033[90m"
    WHITE   = "\033[97m"


def _c(color: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text


def banner():
    art = r"""
██████╗ ███████╗ ██████╗ █████╗         ██╗███████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗        ██║██╔════╝
██████╔╝█████╗  ██║     ███████║        ██║███████╗
██╔══██╗██╔══╝  ██║     ██╔══██║   ██   ██║╚════██║
██║  ██║███████╗╚██████╗██║  ██║██╗╚█████╔╝███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝ ╚════╝ ╚══════╝
                                                                              
    JS Recon & Analysis Pipeline |  By 0xSH1N3 
    (version="1.0") . ⚠️ only for Educational purpose 
    """
    print(_c(Colors.WHITE, art))
    print(_c(Colors.GRAY, f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"))


def info(msg: str):    print(_c(Colors.BLUE,    f"[*] {msg}"))
def success(msg: str): print(_c(Colors.GREEN,   f"[+] {msg}"))
def warn(msg: str):    print(_c(Colors.YELLOW,  f"[!] {msg}"))
def error(msg: str):   print(_c(Colors.RED,     f"[-] {msg}"))
def finding(msg: str): print(_c(Colors.YELLOW,  f"  ► {msg}"))


def section(msg: str):
    bar = "─" * 60
    print()
    print(_c(Colors.MAGENTA, bar))
    print(_c(Colors.MAGENTA + Colors.BOLD, f"  {msg}"))
    print(_c(Colors.MAGENTA, bar))


# ── File helpers ──────────────────────────────────────────────────────────────

def make_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def file_lines(path: str | Path) -> list[str]:
    """Read non-empty stripped lines; return [] if file missing."""
    p = Path(path)
    if not p.exists():
        return []
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip()]


def write_lines(path: str | Path, lines: list[str], mode: str = "w"):
    with open(path, mode, encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n" if lines else "")


def count_lines(path: str | Path) -> int:
    return len(file_lines(path))


def merge_files(sources: list[str | Path], dest: str | Path, dedup: bool = True) -> int:
    seen: set[str] = set()
    lines: list[str] = []
    for src in sources:
        for ln in file_lines(src):
            if dedup:
                if ln not in seen:
                    seen.add(ln)
                    lines.append(ln)
            else:
                lines.append(ln)
    write_lines(dest, lines)
    return len(lines)


# ── Subprocess runner ─────────────────────────────────────────────────────────

def run_cmd(
    cmd: list[str],
    output_file: str | Path | None = None,
    stdin_data: str | None = None,
    timeout: int = 600,
) -> tuple[bool, str]:
    """Run a command. Returns (ok, stderr)."""
    try:
        out_fh = open(output_file, "w", encoding="utf-8") if output_file else subprocess.PIPE
        result = subprocess.run(
            cmd,
            stdout=out_fh,
            stderr=subprocess.PIPE,
            input=stdin_data,
            text=True,
            timeout=timeout,
            env=os.environ,
        )
        if output_file:
            out_fh.close()
        return result.returncode == 0, result.stderr.strip()
    except FileNotFoundError:
        return False, f"Tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"Timed out after {timeout}s"
    except Exception as e:
        return False, str(e)


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def check_tools(tools: list[str]) -> dict[str, bool]:
    results = {t: tool_exists(t) for t in tools}
    for t, found in results.items():
        (success if found else warn)(f"{t} {'found' if found else 'not found – some steps may be skipped'}")
    return results


# ── Noise filter ──────────────────────────────────────────────────────────────

NOISY_JS_PATTERNS = [
    "google-analytics.com", "googletagmanager.com", "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com", "ajax.googleapis.com", "facebook.net",
    "twitter.com/widgets", "hotjar.com", "intercom.io", "fullstory.com",
    "segment.com", "mixpanel.com", "amplitude.com", "newrelic.com",
    "datadog-browser-agent", "sentry.io", "jquery.min.js", "bootstrap.min.js",
    "lodash.min.js", "moment.min.js", "fontawesome",
]


def is_noisy_js(url: str) -> bool:
    u = url.lower()
    return any(p in u for p in NOISY_JS_PATTERNS)


# ══════════════════════════════════════════════════════════════════════════════
#  RECON PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

class ReconPipeline:
    """Subdomain discovery, live host filtering, URL collection, crawling, scanning."""

    def __init__(self, target: str, output_dir: str | None = None, threads: int = 50):
        self.target   = target.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        self.out_dir  = Path(output_dir or f"{self.target}_recon")
        self.threads  = threads

        self.subfinder_out = self.out_dir / "subfinder.txt"
        self.httpx_out     = self.out_dir / "httpx.txt"
        self.wayback_out   = self.out_dir / "waybackurls.txt"
        self.gau_out       = self.out_dir / "gau.txt"
        self.katana_out    = self.out_dir / "katana.txt"
        self.nuclei_out    = self.out_dir / "nuclei.txt"
        self.all_urls_out  = self.out_dir / "all_urls.txt"

    # ── Step 1: Subdomain enumeration ─────────────────────────────────────────

    def run_subfinder(self) -> bool:
        info("Running subfinder...")
        if not tool_exists("subfinder"):
            warn("subfinder not found, skipping")
            return False
        ok, err = run_cmd(
            ["subfinder", "-d", self.target, "-silent", "-all", "-t", str(self.threads)],
            output_file=self.subfinder_out, timeout=300,
        )
        if ok or self.subfinder_out.exists():
            success(f"subfinder → {count_lines(self.subfinder_out)} subdomains found")
            return True
        error(f"subfinder failed: {err}")
        return False

    # ── Step 2: Live host filtering ───────────────────────────────────────────

    def run_httpx(self) -> bool:
        info("Running httpx to filter live hosts...")
        if not tool_exists("httpx"):
            warn("httpx not found, skipping")
            return False
        if not self.subfinder_out.exists() or count_lines(self.subfinder_out) == 0:
            warn("No subdomains to probe, skipping httpx")
            return False
        ok, err = run_cmd(
            ["httpx", "-silent", "-l", str(self.subfinder_out),
             "-threads", str(self.threads), "-follow-redirects",
             "-status-code", "-title", "-tech-detect", "-no-color"],
            output_file=self.httpx_out, timeout=600,
        )
        if ok or self.httpx_out.exists():
            success(f"httpx → {count_lines(self.httpx_out)} live hosts found")
            return True
        error(f"httpx failed: {err}")
        return False

    # ── Step 3: Wayback + GAU ─────────────────────────────────────────────────

    def run_waybackurls(self) -> bool:
        info("Running waybackurls...")
        if not tool_exists("waybackurls"):
            warn("waybackurls not found, skipping")
            return False
        ok, err = run_cmd(["waybackurls", self.target], output_file=self.wayback_out, timeout=300)
        if ok or self.wayback_out.exists():
            success(f"waybackurls → {count_lines(self.wayback_out)} URLs")
            return True
        error(f"waybackurls failed: {err}")
        return False

    def run_gau(self) -> bool:
        info("Running gau (GetAllURLs)...")
        if not tool_exists("gau"):
            warn("gau not found, skipping")
            return False
        ok, err = run_cmd(
            ["gau", "--threads", str(self.threads), self.target],
            output_file=self.gau_out, timeout=300,
        )
        if ok or self.gau_out.exists():
            success(f"gau → {count_lines(self.gau_out)} URLs")
            return True
        error(f"gau failed: {err}")
        return False

    def merge_url_sources(self):
        sources = [f for f in [self.wayback_out, self.gau_out] if f.exists()]
        if sources:
            n = merge_files(sources, self.wayback_out, dedup=True)
            success(f"Merged URL sources → {n} unique URLs in waybackurls.txt")

    # ── Step 4: Katana crawling ───────────────────────────────────────────────

    def run_katana(self) -> bool:
        info("Running katana for active crawling...")
        if not tool_exists("katana"):
            warn("katana not found, skipping")
            return False

        # Extract clean URLs from httpx rich output
        clean_hosts = []
        for line in file_lines(self.httpx_out):
            parts = line.split()
            if parts:
                clean_hosts.append(parts[0])
        if not clean_hosts:
            clean_hosts = [f"https://{self.target}"]

        target_list = self.out_dir / "katana_targets.txt"
        write_lines(target_list, clean_hosts)

        ok, err = run_cmd(
            ["katana", "-list", str(target_list), "-silent",
             "-jc", "-aff", "-d", "5", "-c", str(self.threads),
             "-o", str(self.katana_out)],
            timeout=600,
        )
        if ok or self.katana_out.exists():
            success(f"katana → {count_lines(self.katana_out)} URLs crawled")
            return True
        error(f"katana failed: {err}")
        return False

    # ── Step 5: Nuclei scanning ───────────────────────────────────────────────

    def run_nuclei(self) -> bool:
        info("Running nuclei on live hosts...")
        if not tool_exists("nuclei"):
            warn("nuclei not found, skipping")
            return False
        if not self.httpx_out.exists() or count_lines(self.httpx_out) == 0:
            warn("No live hosts for nuclei, skipping")
            return False

        live_urls = [line.split()[0] for line in file_lines(self.httpx_out) if line.split()]
        clean_hosts = self.out_dir / "nuclei_targets.txt"
        write_lines(clean_hosts, live_urls)

        ok, err = run_cmd(
            ["nuclei", "-l", str(clean_hosts), "-silent",
             "-severity", "low,medium,high,critical",
             "-c", str(self.threads), "-o", str(self.nuclei_out), "-no-color"],
            timeout=1200,
        )
        if ok or self.nuclei_out.exists():
            success(f"nuclei → {count_lines(self.nuclei_out)} findings")
            return True
        error(f"nuclei failed: {err}")
        return False

    # ── Step 6: Merge all URLs ────────────────────────────────────────────────

    def merge_all_urls(self):
        sources = [s for s in [self.wayback_out, self.katana_out] if s.exists()]
        if sources:
            n = merge_files(sources, self.all_urls_out, dedup=True)
            success(f"all_urls.txt → {n} unique URLs total")

    # ── Full pipeline ─────────────────────────────────────────────────────────

    def run(self, skip_nuclei: bool = False) -> dict:
        section(f"RECON PIPELINE  →  {self.target}")
        make_dir(self.out_dir)
        info(f"Recon output directory: {self.out_dir}/")

        results = {
            "subfinder":   self.run_subfinder(),
            "httpx":       self.run_httpx(),
            "waybackurls": self.run_waybackurls(),
            "gau":         self.run_gau(),
        }
        self.merge_url_sources()
        results["katana"] = self.run_katana()
        if not skip_nuclei:
            results["nuclei"] = self.run_nuclei()
        self.merge_all_urls()

        section("RECON COMPLETE")
        for tool_name, ok in results.items():
            (success if ok else warn)(f"  {'✓' if ok else '✗'}  {tool_name}")

        return results


# ══════════════════════════════════════════════════════════════════════════════
#  JS ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

# ── User-Agent pool ───────────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# ── Secret detection patterns ─────────────────────────────────────────────────

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "api_key":              re.compile(r'(?:api[_\-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,64})["\']?', re.I),
    "generic_token":        re.compile(r'(?:token|access_token|auth_token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,200})["\']?', re.I),
    "secret":               re.compile(r'(?:secret|client_secret|app_secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{8,64})["\']?', re.I),
    "password":             re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,64})["\']', re.I),
    "bearer_token":         re.compile(r'Bearer\s+([A-Za-z0-9\-_\.]{20,500})', re.I),
    "aws_access_key":       re.compile(r'(?:AKIA|AIPA|AROA|ASCA|ASIA)[A-Z0-9]{16}'),
    "aws_secret_key":       re.compile(r'(?:aws_secret|aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.I),
    "s3_bucket":            re.compile(r'[a-zA-Z0-9\-\.]+\.s3(?:\.[a-zA-Z0-9\-]+)?\.amazonaws\.com', re.I),
    "s3_bucket_path":       re.compile(r's3://([a-zA-Z0-9\-\.]+)', re.I),
    "google_api_key":       re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "google_oauth":         re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
    "github_token":         re.compile(r'gh[pousr]_[A-Za-z0-9]{36,255}'),
    "slack_token":          re.compile(r'xox[baprs]-[A-Za-z0-9\-]{10,200}'),
    "stripe_key":           re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}'),
    "twilio_sid":           re.compile(r'AC[a-z0-9]{32}'),
    "firebase_url":         re.compile(r'[a-z0-9\-]+\.firebaseio\.com'),
    "jwt_token":            re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
    "private_key":          re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    "authorization_header": re.compile(r'["\']?Authorization["\']?\s*:\s*["\']([^"\']{10,300})["\']', re.I),
    "internal_ip":          re.compile(r'(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}'),
    "sendgrid_key":         re.compile(r'SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43}'),
    "mailchimp_key":        re.compile(r'[a-f0-9]{32}-us[0-9]{1,2}'),
    "heroku_api":           re.compile(r'[hH]eroku[a-zA-Z0-9 _\t\-]{0,30}["\'\s][0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', re.I),
    "generic_endpoint":     re.compile(r'(?:url|endpoint|base_url|api_url)\s*[=:]\s*["\']?(https?://[^\s"\'<>]{5,200})', re.I),
}

URL_PATTERN           = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{5,300}', re.I)
RELATIVE_PATH_PATTERN = re.compile(r'["\']([/][a-zA-Z0-9_\-./]{2,100})["\']')
JS_EXT_PATTERN        = re.compile(r'\.js(?:\?[^\s"\'<>]*)?$', re.I)

JUNK_VALUES = {"true", "false", "null", "undefined", "none"}


def _make_session(ua_index: int = 0) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3, backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent":      USER_AGENTS[ua_index % len(USER_AGENTS)],
        "Accept":          "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection":      "keep-alive",
    })
    return session


class JSAnalyzer:
    """Full JS analysis pipeline: extract → fetch → scan → report."""

    def __init__(
        self,
        target: str,
        recon_dir: str | Path,
        output_dir: str | Path | None = None,
        threads: int = 20,
        timeout: int = 15,
        filter_noise: bool = True,
    ):
        self.target       = target
        self.recon_dir    = Path(recon_dir)
        self.out_dir      = Path(output_dir or f"{target}_jsrecon")
        self.threads      = threads
        self.timeout      = timeout
        self.filter_noise = filter_noise

        self.js_files_out   = self.out_dir / "js_files.txt"
        self.all_js_content = self.out_dir / "all_js_content.js"
        self.jsecrets_out   = self.out_dir / "jsecrets_all.txt"
        self.secrets_out    = self.out_dir / "potential_secrets.txt"
        self.urls_out       = self.out_dir / "extracted_urls.txt"
        self.report_out     = self.out_dir / "summary_report.txt"

        self._session      = _make_session()
        self._fetch_errors: list[str] = []

    # ── Step 1: Extract JS URLs ───────────────────────────────────────────────

    def extract_js_urls(self) -> list[str]:
        section("JS FILE EXTRACTION")
        info("Collecting JS URLs from recon output...")

        all_urls: set[str] = set()
        for fname in ["waybackurls.txt", "all_urls.txt", "katana.txt"]:
            for url in file_lines(self.recon_dir / fname):
                all_urls.add(url)

        info(f"Total URLs to scan: {len(all_urls)}")

        js_urls: list[str] = []
        for url in all_urls:
            base = url.split("?")[0]
            if JS_EXT_PATTERN.search(base) or ".js?" in url:
                if self.filter_noise and is_noisy_js(url):
                    continue
                js_urls.append(url)

        js_urls = sorted(set(js_urls))
        write_lines(self.js_files_out, js_urls)
        success(f"Extracted {len(js_urls)} unique JS URLs → js_files.txt")
        return js_urls

    # ── Step 2: Fetch JS files ────────────────────────────────────────────────

    def _fetch_single(self, url: str) -> Optional[tuple[str, str]]:
        try:
            resp = self._session.get(url, timeout=self.timeout, verify=False)
            if resp.status_code == 200 and resp.text.strip():
                return url, resp.text
            return None
        except requests.exceptions.Timeout:
            self._fetch_errors.append(f"TIMEOUT: {url}")
            return None
        except requests.exceptions.SSLError:
            try:
                r2 = self._session.get(url.replace("https://", "http://", 1), timeout=self.timeout, verify=False)
                if r2.status_code == 200 and r2.text.strip():
                    return url, r2.text
            except Exception:
                pass
            return None
        except Exception as e:
            self._fetch_errors.append(f"ERROR: {url} → {e}")
            return None

    def fetch_js_files(self, js_urls: list[str]) -> dict[str, str]:
        section("JS FETCHING ENGINE")
        info(f"Fetching {len(js_urls)} JS files with {self.threads} threads...")

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        results: dict[str, str] = {}
        failed = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {executor.submit(self._fetch_single, url): url for url in js_urls}
            done = 0
            for future in as_completed(future_map):
                done += 1
                result = future.result()
                if result:
                    results[result[0]] = result[1]
                else:
                    failed += 1
                if done % 10 == 0 or done == len(js_urls):
                    info(f"  Progress: {done}/{len(js_urls)} | ✓ {len(results)} | ✗ {failed}")

        success(f"Fetched {len(results)} JS files ({failed} failed)")

        # Write combined JS
        with open(self.all_js_content, "w", encoding="utf-8", errors="replace") as f:
            for url, content in results.items():
                f.write(f"\n\n// {'='*70}\n// Source: {url}\n// {'='*70}\n\n")
                f.write(content)
                f.write("\n")
        success(f"Combined JS → all_js_content.js ({self.all_js_content.stat().st_size // 1024} KB)")

        return results

    # ── Step 3: jsecrets integration ──────────────────────────────────────────

    def run_jsecrets(self) -> bool:
        section("JSECRETS SCAN")
        if not tool_exists("jsecrets"):
            warn("jsecrets not found, skipping")
            return False
        if not self.all_js_content.exists():
            warn("all_js_content.js missing, skipping jsecrets")
            return False

        info("Running jsecrets on combined JS content...")
        with open(self.all_js_content, "r", encoding="utf-8", errors="replace") as f:
            js_data = f.read()

        ok, err = run_cmd(
            ["jsecrets", "-i", "-"],
            output_file=self.jsecrets_out,
            stdin_data=js_data,
            timeout=300,
        )
        if ok or self.jsecrets_out.exists():
            success(f"jsecrets → {count_lines(self.jsecrets_out)} findings → jsecrets_all.txt")
            return True
        error(f"jsecrets failed: {err}")
        return False

    # ── Step 4: Regex secret detection ───────────────────────────────────────

    def detect_secrets(self, fetched: dict[str, str]) -> list[dict]:
        section("REGEX SECRET DETECTION")
        info(f"Scanning {len(fetched)} JS files for secrets...")

        findings: list[dict] = []

        for url, content in fetched.items():
            for pattern_name, regex in SECRET_PATTERNS.items():
                for match in regex.findall(content):
                    value = match if isinstance(match, str) else match[0]
                    if len(value) < 6:
                        continue
                    if value.lower() in JUNK_VALUES:
                        continue
                    if all(c in "{}<>$" for c in value):
                        continue
                    findings.append({"type": pattern_name, "value": value[:200], "source": url})

        # Write output
        lines: list[str] = []
        for f in findings:
            lines += [f"[{f['type'].upper()}]  {f['value']}", f"  → Source: {f['source']}", ""]
        write_lines(self.secrets_out, lines)

        unique = {(f["type"], f["value"]) for f in findings}
        success(f"Regex detection → {len(unique)} unique secrets → potential_secrets.txt")

        type_counts: dict[str, int] = {}
        for f in findings:
            type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1
        for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            finding(f"{t}: {count} match(es)")

        return findings

    # ── Step 5: Endpoint extraction ───────────────────────────────────────────

    def extract_endpoints(self, fetched: dict[str, str]) -> list[str]:
        section("ENDPOINT EXTRACTION")
        info("Extracting URLs and endpoints from JS files...")

        all_endpoints: set[str] = set()
        skip_exts = (".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico")

        for url, content in fetched.items():
            for match in URL_PATTERN.findall(content):
                all_endpoints.add(match.rstrip(".,;\"'"))
            for match in RELATIVE_PATH_PATTERN.findall(content):
                if len(match) > 2 and not match.endswith(skip_exts):
                    all_endpoints.add(match)

        sorted_endpoints = sorted(all_endpoints)
        write_lines(self.urls_out, sorted_endpoints)
        success(f"Extracted {len(sorted_endpoints)} unique endpoints → extracted_urls.txt")
        return sorted_endpoints

    # ── Step 6: Summary report ────────────────────────────────────────────────

    def write_report(self, js_urls: list, fetched: dict, secrets: list, endpoints: list):
        section("GENERATING SUMMARY REPORT")

        type_counts: dict[str, int] = {}
        for f in secrets:
            type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1

        js_kb = self.all_js_content.stat().st_size // 1024 if self.all_js_content.exists() else 0

        lines = [
            "=" * 70,
            "  RECON + JS ANALYSIS SUMMARY REPORT",
            f"  Target  : {self.target}",
            f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 70, "",
            "[RECON]",
            f"  Subfinder subdomains  : {count_lines(self.recon_dir / 'subfinder.txt')}",
            f"  Live hosts (httpx)    : {count_lines(self.recon_dir / 'httpx.txt')}",
            f"  Wayback/GAU URLs      : {count_lines(self.recon_dir / 'waybackurls.txt')}",
            f"  Katana crawl URLs     : {count_lines(self.recon_dir / 'katana.txt')}",
            f"  Nuclei findings       : {count_lines(self.recon_dir / 'nuclei.txt')}",
            "", "[JS ANALYSIS]",
            f"  JS files discovered   : {len(js_urls)}",
            f"  JS files fetched      : {len(fetched)}",
            f"  Fetch failures        : {len(self._fetch_errors)}",
            f"  Combined JS size      : {js_kb} KB",
            "", "[SECRETS FOUND]",
        ]

        if type_counts:
            for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  {t:<30} : {count}")
        else:
            lines.append("  No secrets detected")

        lines += [
            "", "[ENDPOINTS]",
            f"  Unique endpoints      : {len(endpoints)}",
            "", "[OUTPUT FILES]",
            f"  {self.out_dir}/js_files.txt",
            f"  {self.out_dir}/all_js_content.js",
            f"  {self.out_dir}/jsecrets_all.txt",
            f"  {self.out_dir}/potential_secrets.txt",
            f"  {self.out_dir}/extracted_urls.txt",
            "", "[FETCH ERRORS]",
        ]
        if self._fetch_errors:
            for e in self._fetch_errors[:20]:
                lines.append(f"  {e}")
            if len(self._fetch_errors) > 20:
                lines.append(f"  ... and {len(self._fetch_errors) - 20} more")
        else:
            lines.append("  None")

        lines.append("=" * 70)
        write_lines(self.report_out, lines)
        success("Report saved → summary_report.txt")

        print()
        for line in lines:
            print(f"  {line}")

    # ── Full pipeline ─────────────────────────────────────────────────────────

    def run(self) -> dict:
        make_dir(self.out_dir)
        info(f"JS recon output directory: {self.out_dir}/")

        js_urls = self.extract_js_urls()
        if not js_urls:
            warn("No JS files found. Exiting JS analysis.")
            return {"js_urls": 0, "fetched": 0, "secrets": 0, "endpoints": 0}

        fetched   = self.fetch_js_files(js_urls)
        self.run_jsecrets()
        secrets   = self.detect_secrets(fetched)
        endpoints = self.extract_endpoints(fetched)
        self.write_report(js_urls, fetched, secrets, endpoints)

        return {
            "js_urls":   len(js_urls),
            "fetched":   len(fetched),
            "secrets":   len(secrets),
            "endpoints": len(endpoints),
        }


# ══════════════════════════════════════════════════════════════════════════════
#  CLI ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════

REQUIRED_TOOLS = ["subfinder", "httpx", "waybackurls", "gau", "katana", "nuclei", "jsecrets"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="jsrecon.py",
        description="JS Recon & Secret Hunter — Bug Bounty Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jsrecon.py -d example.com
  python jsrecon.py -d example.com --skip-nuclei --threads 30
  python jsrecon.py -d example.com --skip-recon
  python jsrecon.py -d example.com --js-only --timeout 20
  python jsrecon.py -d example.com --check-tools
        """,
    )
    parser.add_argument("-d", "--domain",         required=True,      metavar="DOMAIN",  help="Target domain (e.g. example.com)")
    parser.add_argument("--threads",              type=int, default=20, metavar="N",     help="Thread count (default: 20)")
    parser.add_argument("--timeout",              type=int, default=15, metavar="SECS",  help="JS fetch timeout in seconds (default: 15)")
    parser.add_argument("--skip-recon",           action="store_true",                   help="Skip recon pipeline (use existing output)")
    parser.add_argument("--skip-nuclei",          action="store_true",                   help="Skip nuclei scan")
    parser.add_argument("--skip-js",              action="store_true",                   help="Skip JS analysis pipeline")
    parser.add_argument("--js-only",              action="store_true",                   help="Run JS analysis only (implies --skip-recon)")
    parser.add_argument("--no-filter-noise",      action="store_true",                   help="Include analytics/CDN JS files")
    parser.add_argument("--recon-dir",            metavar="DIR",                         help="Custom recon output directory")
    parser.add_argument("--jsrecon-dir",          metavar="DIR",                         help="Custom JS recon output directory")
    parser.add_argument("--check-tools",          action="store_true",                   help="Check tool availability and exit")
    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    target = (
        args.domain.strip().lower()
        .removeprefix("http://")
        .removeprefix("https://")
        .split("/")[0]
    )

    recon_dir   = args.recon_dir   or f"{target}_recon"
    jsrecon_dir = args.jsrecon_dir or f"{target}_jsrecon"

    section("TOOL AVAILABILITY CHECK")
    check_tools(REQUIRED_TOOLS)
    if args.check_tools:
        sys.exit(0)

    # ── Phase 1: Recon ────────────────────────────────────────────────────────

    if not (args.skip_recon or args.js_only):
        ReconPipeline(target=target, output_dir=recon_dir, threads=args.threads).run(
            skip_nuclei=args.skip_nuclei
        )
    else:
        info("Skipping recon pipeline (using existing output)")

    if args.skip_js:
        success("Done (JS analysis skipped).")
        sys.exit(0)

    # ── Phase 2: JS Analysis ──────────────────────────────────────────────────

    recon_path = Path(recon_dir)
    if not recon_path.exists():
        error(f"Recon directory '{recon_dir}' not found.")
        error("Run without --skip-recon first, or set --recon-dir correctly.")
        sys.exit(1)

    js_results = JSAnalyzer(
        target=target,
        recon_dir=recon_path,
        output_dir=jsrecon_dir,
        threads=args.threads,
        timeout=args.timeout,
        filter_noise=not args.no_filter_noise,
    ).run()

    # ── Final summary ─────────────────────────────────────────────────────────

    section("ALL DONE")
    success(f"Target    : {target}")
    success(f"Recon dir : {recon_dir}/")
    success(f"JS dir    : {jsrecon_dir}/")

    if js_results["secrets"] > 0:
        warn(f"⚠  {js_results['secrets']} potential secrets — review potential_secrets.txt")
    else:
        info("No secrets detected in regex scan")

    info(f"JS files  : {js_results['js_urls']} found, {js_results['fetched']} fetched")
    info(f"Endpoints : {js_results['endpoints']} extracted")


if __name__ == "__main__":
    start = time.time()
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user. Partial results may be saved.")
        sys.exit(130)
    finally:
        print(f"\n  Total time: {time.time() - start:.1f}s\n")
