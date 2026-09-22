#!/usr/bin/env python3
"""
URL Security Exposure Checker.py
-----------------
Security check script scoped to a pre-approved asset list (targets.txt).

Purpose:
- For pre-approved (own) assets only, check the following:
    1) Whether the page is directly accessible without authentication
       (based on HTTP status code)
    2) Whether the GET method is allowed
    3) Whether the response body exposes suspected PII patterns
       (passport number, phone number, email, etc.) without masking
       (only the count is recorded; the original value is partially
       masked before being logged)
    4) Guidance for checking search-engine indexing (the script does NOT
       perform automated "site:" scraping — it only prints manual queries,
       to avoid enabling automated recon/dumping against third-party sites)

Core safeguards:
- No URL is scanned unless its domain is listed in targets.txt.
- The scan target must be an asset you have administrative authority over;
  the script requires explicit confirmation before running.
- PII is never printed/stored in raw form — it is always masked.

Usage:
    1) List approved domains in targets.txt, one per line (e.g. example.com)
    2) List URLs to check in urls.txt, one per line
    3) python URL Security Exposure Checker.py --targets targets.txt --urls urls.txt
"""

import argparse
import re
import sys
import csv
import time
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("The 'requests' library is required: pip install requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# PII patterns (detection only — raw values are masked before being recorded)
# ---------------------------------------------------------------------------
PII_PATTERNS = {
    "passport_number_kr": re.compile(r"\b[A-Z]\d{8}\b"),
    "phone_number(010-XXXX-XXXX)": re.compile(r"\b010-?\d{4}-?\d{4}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "resident_registration_number_format": re.compile(r"\b\d{6}-?[1-4]\d{6}\b"),
    # Name - Korean (2-4 Hangul syllables) / English (passport style
    # "GIVEN SURNAME", e.g. TEST KIM)
    "name(korean)": re.compile(r"[\uac00-\ud7a3]{2,4}"),
    "name(english)": re.compile(r"\b[A-Z]{2,}\s[A-Z]{2,}\b"),
    # 6-char mix of uppercase letters and digits (pure-letter or pure-digit
    # 6-char strings are excluded to reduce false positives)
    "reservation_code_format(6char_alnum_mixed)": re.compile(
        r"\b(?=[A-Z0-9]{6}\b)(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{6}\b"
    ),
}


def mask(value: str) -> str:
    """Mask a PII value so the raw text is never written to logs."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def load_lines(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def is_allowed(url: str, allowed_domains: set[str]) -> bool:
    """Return True only if the URL's domain is in the approved list."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in allowed_domains)


def check_unauth_access(url: str, timeout: int = 10) -> dict:
    """Check whether the page is accessible via a plain GET with no auth
    headers/cookies."""
    result = {
        "url": url,
        "method_get_allowed": None,
        "status_code": None,
        "unauth_accessible": None,
        "pii_findings": {},
        "error": None,
    }
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                             headers={"User-Agent": "internal-asset-scanner/1.0"})
        result["status_code"] = resp.status_code
        result["method_get_allowed"] = resp.status_code != 405
        # Treat as "accessible without auth" if the response is a 2xx/3xx
        # and it wasn't redirected to a login page
        redirected_to_login = any(
            kw in resp.url.lower() for kw in ["login", "signin", "auth"]
        )
        result["unauth_accessible"] = resp.status_code < 400 and not redirected_to_login

        if result["unauth_accessible"]:
            body = resp.text
            for label, pattern in PII_PATTERNS.items():
                matches = pattern.findall(body)
                if matches:
                    result["pii_findings"][label] = {
                        "count": len(matches),
                        "sample_masked": [mask(m) for m in matches[:3]],
                    }
    except requests.RequestException as e:
        result["error"] = str(e)

    return result


def print_indexing_check_guide(domains: set[str]) -> None:
    """Search-engine indexing is checked manually, not via automated
    crawling/scraping."""
    print("\n[Search engine indexing - manual check guidance]")
    print("Run the queries below yourself on Google/Naver etc. to verify.")
    print("(Automated search-engine crawling/scraping is excluded from this "
          "script as it may violate terms of service)\n")
    for d in sorted(domains):
        print(f"  site:{d} name")        
        print(f"  site:{d} passport")
        print(f"  site:{d} passportNo")
        print(f"  site:{d} reservation")
        print(f"  site:{d} booking") 

        print(f"  site:{d} inurl:reservation")        
        print(f"  site:{d} inurl:booking")      
        print(f"  site:{d} inurl:reservation/detail")    
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Security scanner scoped to a pre-approved asset list")
    parser.add_argument("--targets", required=True,
                         help="File listing approved domains (e.g. targets.txt)")
    parser.add_argument("--urls", required=True,
                         help="File listing URLs to check (e.g. urls.txt)")
    parser.add_argument("--out", default="scan_result.csv",
                         help="Path to save the result CSV")
    parser.add_argument("--delay", type=float, default=1.0,
                         help="Delay between requests, in seconds")
    args = parser.parse_args()

    allowed_domains = set(d.lower() for d in load_lines(args.targets))
    urls = load_lines(args.urls)

    print(f"Approved domains: {sorted(allowed_domains)}")
    confirm = input(
        "\nDo you have administrative authority/approval to scan the domains "
        "above? Proceed only for assets you are responsible for. "
        "(type 'yes' to continue): "
    )
    if confirm.strip().lower() != "yes":
        print("No confirmation received. Exiting.")
        sys.exit(0)

    rows = []
    skipped = []

    for url in urls:
        if not is_allowed(url, allowed_domains):
            skipped.append(url)
            continue

        print(f"Checking: {url}")
        result = check_unauth_access(url)
        rows.append(result)
        time.sleep(args.delay)

    if skipped:
        print(f"\n[Skipped] {len(skipped)} URL(s) not scanned because their "
              f"domain is not in targets.txt:")
        for u in skipped:
            print(f"  - {u}")

    # Save results
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scan_time", "url", "status_code", "get_allowed",
            "unauth_accessible", "pii_labels_found", "pii_detail", "error"
        ])
        for r in rows:
            pii_labels = ", ".join(r["pii_findings"].keys()) if r["pii_findings"] else ""
            pii_detail = "; ".join(
                f"{label}={info['count']} (e.g. {info['sample_masked']})"
                for label, info in r["pii_findings"].items()
            )
            writer.writerow([
                datetime.now().isoformat(timespec="seconds"),
                r["url"], r["status_code"], r["method_get_allowed"],
                r["unauth_accessible"], pii_labels, pii_detail, r["error"] or ""
            ])

    # Print summary
    print("\n=== Summary ===")
    risky = [r for r in rows if r["unauth_accessible"] and r["pii_findings"]]
    print(f"Total checked: {len(rows)} / accessible without auth + suspected "
          f"PII found: {len(risky)}")
    for r in risky:
        print(f"  \u26a0 {r['url']}")
        for label, info in r["pii_findings"].items():
            print(f"      - {label}: {info['count']} match(es) "
                  f"(sample: {info['sample_masked']})")

    print(f"\nDetailed results: {args.out}")

    print_indexing_check_guide(allowed_domains)


if __name__ == "__main__":
    main()
