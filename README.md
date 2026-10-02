# pentrix-headers

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#install)

Grade any website's HTTP security headers from **A to F** with one-line fix advice for every finding. Zero dependencies, standard library only.

## Features

- Scans 6 header groups: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options` (or CSP `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- Letter grade A-F mapped from a 100-point rubric (documented in code)
- One-line fix advice with the exact header value to set, for every FAIL and WARN
- Follows redirects by default and reports the final URL; `--no-redirect` to stop at the first hop
- Scheme optional: `example.com` is scanned as `https://example.com`
- Clean exit codes and clear error messages for DNS failures, timeouts, and bad input
- Save the report with `-o/--output`

**Non-intrusive:** each scan sends exactly one GET request. No crawling, no fuzzing, no payloads.

## Grading rubric

Every scan starts at 100 points. Deductions:

| Check | Deduction | When |
|---|---|---|
| Strict-Transport-Security | -25 FAIL | header missing |
| Strict-Transport-Security | -10 WARN | `max-age` below 31536000 |
| Strict-Transport-Security | -5 WARN | `includeSubDomains` missing |
| Content-Security-Policy | -20 FAIL | header missing |
| Content-Security-Policy | -10 WARN | only `Report-Only` variant set |
| Clickjacking protection | -10 WARN | no `X-Frame-Options` and no CSP `frame-ancestors` |
| X-Content-Type-Options | -10 FAIL | missing or not `nosniff` |
| Referrer-Policy | -5 WARN | header missing |
| Permissions-Policy | -5 WARN | header missing |

Grades: **A** >= 90, **B** >= 80, **C** >= 70, **D** >= 60, **F** < 60.

## Install

Zero dependencies. Python 3.8 or newer is all you need.

```bash
git clone https://github.com/mizazhaider-ceh/pentrix-headers.git
cd pentrix-headers
python3 headers.py --help
```

## Usage

```bash
# basic scan
python3 headers.py https://example.com

# scheme is optional, https is assumed
python3 headers.py example.com

# custom timeout
python3 headers.py https://example.com --timeout 5

# stop at redirects instead of following them
python3 headers.py http://example.com --no-redirect

# save the report to a file
python3 headers.py https://github.com -o report.txt
```

### Sample output: a site with no headers

```text
$ python3 headers.py https://example.com
pentrix-headers v1.0.0 scan report
============================================================
Target:      https://example.com
HTTP status: 200

RESULT CHECK        DETAIL
------------------------------------------------------------
FAIL (-25) HSTS         Strict-Transport-Security missing
       -> Fix: add header Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
FAIL (-20) CSP          Content-Security-Policy missing
       -> Fix: add header Content-Security-Policy: default-src 'self'; frame-ancestors 'self'
WARN (-10) Framing      No X-Frame-Options and no CSP frame-ancestors: clickjacking possible
       -> Fix: add header X-Frame-Options: SAMEORIGIN (or set frame-ancestors 'self' in CSP)
FAIL (-10) MIME         X-Content-Type-Options missing
       -> Fix: add header X-Content-Type-Options: nosniff
WARN (-5) Referrer     Referrer-Policy missing
       -> Fix: add header Referrer-Policy: strict-origin-when-cross-origin
WARN (-5) Permissions  Permissions-Policy missing
       -> Fix: add header Permissions-Policy: camera=(), microphone=(), geolocation=()

Score: 25/100
Grade: F
============================================================
```

### Sample output: a well-hardened site

```text
$ python3 headers.py https://github.com
pentrix-headers v1.0.0 scan report
============================================================
Target:      https://github.com
HTTP status: 200

RESULT CHECK        DETAIL
------------------------------------------------------------
PASS   HSTS         Strict-Transport-Security present with strong max-age: max-age=31536000; includeSubdomains; preload
PASS   CSP          Content-Security-Policy present: default-src 'none'; base-uri 'self'; child-src github.githubassets.com github.com/assets-c...
PASS   Framing      X-Frame-Options: DENY blocks clickjacking
PASS   MIME         X-Content-Type-Options: nosniff
PASS   Referrer     Referrer-Policy: origin-when-cross-origin, strict-origin-when-cross-origin
WARN (-5) Permissions  Permissions-Policy missing
       -> Fix: add header Permissions-Policy: camera=(), microphone=(), geolocation=()

Score: 95/100
Grade: A
============================================================
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | scan completed |
| 1 | network or fetch error (DNS failure, timeout, refused redirect) |
| 2 | bad arguments |

## License

MIT. See [LICENSE](LICENSE).
