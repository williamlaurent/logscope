#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Apache / Web Log Analyzer (Logscope)
by Willmet 
-----------------------------------
- Supports Apache/Nginx (combined/common/vhost)
- Auto format detection
- Accepts .log, .txt, .gz, etc.
- Writes results to ./Results/
"""

import os
import re
import sys
import gzip
import json
import platform
from datetime import datetime
from collections import Counter

# ----- Color Setup -----
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COK = Fore.GREEN + Style.BRIGHT
    CINFO = Fore.CYAN + Style.BRIGHT
    CWARN = Fore.YELLOW + Style.BRIGHT
    CERR = Fore.RED + Style.BRIGHT
    CHEAD = Fore.MAGENTA + Style.BRIGHT
    CRESET = Style.RESET_ALL
except Exception:
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = Style = _Dummy()
    COK = CINFO = CWARN = CERR = CHEAD = CRESET = ""

APP_NAME = "Apache / Web Log Analyzer"
RESULTS_DIR = "Results"

# ----- Utility functions -----
def clear_screen():
    os.system("cls" if platform.system().lower().startswith("win") else "clear")

def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)

def open_any(path):
    if path.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")

def parse_apache_time(ts):
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        return None

def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default

def human_bytes(n):
    try:
        n = int(n)
    except Exception:
        return str(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"

def bar(counter, top=10):
    total = sum(counter.values())
    lines = []
    for key, cnt in counter.most_common(top):
        frac = cnt / total if total else 0
        bars = int(frac * 30)
        lines.append(f"{key:>8} | {'█'*bars:<30} {cnt} ({frac*100:.1f}%)")
    return "\n".join(lines) or "(no data)"

# ----- Regex Patterns -----
REGEX_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)?\s*(?P<path>[^"]*?)\s*(?P<protocol>HTTP/\d\.\d)?"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)"'
)
REGEX_COMMON = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)?\s*(?P<path>[^"]*?)\s*(?P<protocol>HTTP/\d\.\d)?"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<size>\S+)'
)

# With Virtual Host
REGEX_VHOST_PREFIX = r'^(?P<vhost>\S+)\s+'
REGEX_COMBINED_VHOST = re.compile(REGEX_VHOST_PREFIX + REGEX_COMBINED.pattern)
REGEX_COMMON_VHOST = re.compile(REGEX_VHOST_PREFIX + REGEX_COMMON.pattern)

# ----- Analyzer Core -----
class Analyzer:
    def __init__(self):
        self.total = 0
        self.parsed = 0
        self.unparsed = 0
        self.bytes_total = 0
        self.status = Counter()
        self.methods = Counter()
        self.ips = Counter()
        self.paths = Counter()

    def parse_line(self, line):
        self.total += 1
        line = line.rstrip("\n")

        for regex in [REGEX_COMBINED, REGEX_COMMON, REGEX_COMBINED_VHOST, REGEX_COMMON_VHOST]:
            m = regex.match(line)
            if m:
                d = m.groupdict()
                self._record(d)
                return True

        self.unparsed += 1
        return False

    def _record(self, d):
        self.parsed += 1
        self.status[d.get("status", "-")] += 1
        self.methods[d.get("method", "-")] += 1
        self.ips[d.get("ip", "-")] += 1
        path = d.get("path", "-").split("?")[0]
        self.paths[path] += 1
        self.bytes_total += safe_int(d.get("size", 0))

# ----- Reporting -----
def generate_report(an, src):
    lines = [
        f"{APP_NAME} - Analysis Report",
        "="*60,
        f"Source File : {os.path.basename(src)}",
        f"Total Lines : {an.total}",
        f"Parsed      : {an.parsed}",
        f"Unparsed    : {an.unparsed}",
        f"Bytes Sent  : {human_bytes(an.bytes_total)}",
        "",
        "== Status Codes ==",
        bar(an.status, 20),
        "",
        "== HTTP Methods ==",
        bar(an.methods, 10),
        "",
        "== Top 20 IP Addresses ==",
        *[f"{ip:>16} : {cnt}" for ip, cnt in an.ips.most_common(20)],
        "",
        "== Top 20 Requested Paths ==",
        *[f"{cnt:>6}  {path}" for path, cnt in an.paths.most_common(20)],
    ]
    return "\n".join(lines)

def write_report(report_text, src):
    ensure_results_dir()
    base = os.path.basename(src)
    name = os.path.splitext(base)[0]
    out_path = os.path.join(RESULTS_DIR, f"{name}_analysis.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_text)
    return out_path

# ----- CLI Interaction -----
def main():
    clear_screen()
    print(CHEAD + "="*68)
    print(f"{APP_NAME}".center(68))
    print("="*68 + CRESET)
    print(CINFO + "Accepts .log, .txt, .gz | Output in ./Results/ | Ctrl+C safe\n")

    try:
        log_path = input(CHEAD + "Enter log file path: " + CRESET).strip().strip('"').strip("'")
        if not log_path:
            print(CERR + "No file path provided.")
            return
        if not os.path.isfile(log_path):
            print(CERR + f"File not found: {log_path}")
            return

        print(CINFO + f"\nAnalyzing {log_path} ...\n")

        analyzer = Analyzer()
        line_count = 0

        with open_any(log_path) as f:
            for line in f:
                analyzer.parse_line(line)
                line_count += 1
                if line_count % 200000 == 0:
                    print(CINFO + f"... processed {line_count:,} lines")

        report = generate_report(analyzer, log_path)
        out_file = write_report(report, log_path)

        print(COK + f"\nAnalysis complete! Report saved to: {out_file}")
    except KeyboardInterrupt:
        print(CWARN + "\nOperation cancelled by user.")
    except Exception as e:
        print(CERR + f"\nError: {e}")
    finally:
        input(CINFO + "\nPress Enter to clear screen and exit... " + CRESET)
        clear_screen()

if __name__ == "__main__":
    main()
