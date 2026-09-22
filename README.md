# URL-Security-Exposure-Checker — Allowlist-based PII Exposure Checker

A Python script that, scoped strictly to an approved domain allowlist,
checks whether pages are accessible without authentication and whether
the response body exposes PII patterns (passport number, phone number,
email, resident-registration-number format, name, etc.).

Built in response to a real-world incident — where an unauthenticated 
reservation-lookup URL scheme was crawled and indexed by search engines, 
exposing unmasked passport numbers, as a way to self-check similar issues in other services.

---

## ⚠️ Read before use (Legal & Ethical Notice)

**This tool must only be used against assets you own, or for which you
have explicit written authorization.**

- Running this tool against third-party websites, services, or systems
  without authorization may violate applicable laws (e.g. computer
  fraud / unauthorized access statutes) in your jurisdiction.
- The script is designed to refuse scanning any URL whose domain is not
  listed in `targets.txt`, but **bypassing this safeguard, or adding
  unauthorized domains to targets.txt yourself, is entirely your own
  responsibility.**
- The script prompts for confirmation ("Do you have authority/approval
  to scan these domains?") before running — do not proceed unless the
  answer is genuinely yes.
- This tool is meant to help you discover exposure; any finding must be
  reported immediately to the owning organization (or your internal
  security team) and handled through a responsible disclosure process.
- The author accepts no liability for misuse of this tool (see the MIT
  License terms).

For these reasons, this repository is provided as reference code for
**white-box self-assessment of your own assets** only. For real
penetration testing needs, use a contracted security firm or your
internal security team.

---

## Features

| Feature | Description |
|---|---|
| Domain allowlist enforcement | Only scans domains listed in `targets.txt`; everything else is auto-skipped |
| Pre-run confirmation prompt | Will not run without explicit `yes` confirmation |
| Unauthenticated access check | Determines accessibility via status code and redirect behavior on a plain GET request (no auth headers/cookies) |
| PII pattern detection | Passport number, phone number, email, resident-registration-number format, name (Korean/English), etc. |
| Masking | Detected values are logged/saved only in masked form (first/last 2 chars visible), never raw |
| Search-engine exposure check | No automated crawling — only prints manual `site:domain keyword` queries to run yourself |

## Installation & Usage

```bash
pip install requests

# 1) List only approved domains in targets.txt
echo "example.com" > targets.txt

# 2) List URLs to check in urls.txt
echo "https://example.com/reservation?id=12345" > urls.txt

# 3) Run
python URL Security Exposure Checker.py --targets targets.txt --urls urls.txt
```

Results are saved to `scan_result.csv`, containing masked samples only —
never raw PII values.

## Known Limitations

- Detection is regex/pattern-based, so false positives can occur. The
  Korean name pattern (`[\uac00-\ud7a3]{2,4}`, i.e. 2-4 Hangul syllables) in particular has a high false
  positive rate since it's hard to distinguish from ordinary nouns. For
  production use, narrowing detection to label-based context (e.g. text
  preceded by "Name:", "Passenger:") is recommended.
- GET-method-allowed detection relies on a simple 405-status check, so
  distinguishing 404 (resource not found) from 405 (method not allowed)
  accurately requires testing against a URL that actually exists.
- If OPTIONS is blocked by the server/WAF, the `Allow` header can't be
  retrieved, limiting method-detection accuracy.
- This does not replace a formal penetration test. Deeper checks (auth
  bypass, session management flaws, etc.) require dedicated tools
  (OWASP ZAP, Burp Suite, etc.) and trained personnel.

## License

MIT License — subject to the liability terms in the "Read before use"
section above.
