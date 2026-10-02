#!/usr/bin/env python3
"""pentrix-headers: HTTP security headers analyzer.

Fetches a URL and grades the site's response security headers from A to F,
with one-line fix advice for every failing check. Non-intrusive: sends a
single GET request per scan.

Standard library only. No third party dependencies.
"""

import argparse
import sys
import urllib.error
import urllib.request

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Grading rubric
# ---------------------------------------------------------------------------
# Every scan starts at 100 points. Each check can deduct points:
#
#   HSTS (Strict-Transport-Security)             -25 if missing (FAIL)
#                                                -10 if max-age < 31536000 (WARN)
#                                                 -5 if includeSubDomains missing (WARN)
#   CSP (Content-Security-Policy)                -20 if missing (FAIL)
#                                                -10 if only Content-Security-Policy-Report-Only (WARN)
#   Clickjacking protection                      -10 if neither X-Frame-Options
#                                                       nor frame-ancestors in CSP (WARN)
#   X-Content-Type-Options                       -10 if missing or not nosniff (FAIL)
#   Referrer-Policy                               -5 if missing (WARN)
#   Permissions-Policy                            -5 if missing (WARN)
#
# Maximum possible deduction: 25+10+5+20+10+10+10+5+5 = 100, so the worst
# realistic score bottoms out at 0 and typical weak sites land in D/F range.
#
#   A  score >= 90
#   B  score >= 80
#   C  score >= 70
#   D  score >= 60
#   F  score < 60
# ---------------------------------------------------------------------------

HSTS_MIN_MAX_AGE = 31_536_000  # one year in seconds

HSTS_FIX = (
    "Fix: add header "
    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
)
CSP_FIX = (
    "Fix: add header "
    "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'"
)
CSP_RO_FIX = (
    "Fix: replace Content-Security-Policy-Report-Only with an enforcing "
    "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'"
)
XFO_FIX = "Fix: add header X-Frame-Options: SAMEORIGIN (or set frame-ancestors 'self' in CSP)"
XCTO_FIX = "Fix: add header X-Content-Type-Options: nosniff"
REFERRER_FIX = "Fix: add header Referrer-Policy: strict-origin-when-cross-origin"
PERMISSIONS_FIX = "Fix: add header Permissions-Policy: camera=(), microphone=(), geolocation=()"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # returning None aborts the redirect with HTTPError


def normalize_url(raw):
    """Return the URL with a scheme, defaulting to https when missing."""
    raw = raw.strip()
    if not raw:
        return None
    if "://" not in raw:
        return "https://" + raw
    return raw


def fetch(url, timeout, follow_redirects):
    """Fetch the URL with a single GET request.

    Returns (final_url, headers_dict, status_code, redirect_chain).
    Raises urllib.error.URLError / HTTPError on network problems.
    """
    handlers = []
    if not follow_redirects:
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "pentrix-headers/{} (security headers scanner)".format(VERSION)},
        method="GET",
    )
    redirect_chain = []
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # With --no-redirect, redirects surface here as HTTPError.
        if not follow_redirects and exc.code in (301, 302, 303, 307, 308):
            raise SystemExitRedirect(exc.headers.get("Location"), exc.code)
        raise
    final_url = response.geturl()
    # urllib follows redirects silently; rebuild the chain note from history.
    if final_url != url:
        redirect_chain.append((url, final_url))
    headers = {k.lower(): v for k, v in response.headers.items()}
    return final_url, headers, response.status, redirect_chain


class SystemExitRedirect(Exception):
    """Internal signal: a redirect was refused because of --no-redirect."""

    def __init__(self, location, code):
        super().__init__(location)
        self.location = location
        self.code = code


def parse_directives(value):
    """Split a semicolon separated header value into lowercase directives."""
    return [part.strip().lower() for part in value.split(";") if part.strip()]


def check_hsts(headers):
    """Check Strict-Transport-Security. Returns a list of findings."""
    findings = []
    value = headers.get("strict-transport-security")
    if value is None:
        findings.append(("FAIL", "HSTS", -25, "Strict-Transport-Security missing", HSTS_FIX))
        return findings
    directives = parse_directives(value)
    max_age = None
    for directive in directives:
        if directive.startswith("max-age="):
            try:
                max_age = int(directive.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                max_age = None
    if max_age is None or max_age < HSTS_MIN_MAX_AGE:
        findings.append(
            ("WARN", "HSTS", -10,
             "Strict-Transport-Security max-age too short (< {}): {}".format(HSTS_MIN_MAX_AGE, value),
             HSTS_FIX))
    elif "includesubdomains" not in directives:
        findings.append(
            ("WARN", "HSTS", -5,
             "Strict-Transport-Security lacks includeSubDomains: {}".format(value),
             HSTS_FIX))
    if not findings:
        findings.append(("PASS", "HSTS", 0,
                         "Strict-Transport-Security present with strong max-age: {}".format(value), None))
    return findings


def check_csp(headers):
    """Check Content-Security-Policy (enforcing, not report-only)."""
    findings = []
    csp = headers.get("content-security-policy")
    report_only = headers.get("content-security-policy-report-only")
    if csp:
        findings.append(("PASS", "CSP", 0,
                         "Content-Security-Policy present: {}".format(trim(csp)), None))
    elif report_only:
        findings.append(("WARN", "CSP", -10,
                         "Only Content-Security-Policy-Report-Only is set; nothing is enforced",
                         CSP_RO_FIX))
    else:
        findings.append(("FAIL", "CSP", -20, "Content-Security-Policy missing", CSP_FIX))
    return findings


def check_framing(headers):
    """Check clickjacking protection via X-Frame-Options or CSP frame-ancestors."""
    xfo = headers.get("x-frame-options", "").strip().upper()
    csp = headers.get("content-security-policy", "")
    frame_ancestors = any(
        d.startswith("frame-ancestors") for d in parse_directives(csp)
    )
    if xfo in ("DENY", "SAMEORIGIN"):
        return [("PASS", "Framing", 0,
                 "X-Frame-Options: {} blocks clickjacking".format(xfo), None)]
    if frame_ancestors:
        return [("PASS", "Framing", 0,
                 "CSP frame-ancestors directive blocks clickjacking (no X-Frame-Options needed)",
                 None)]
    if xfo:
        return [("WARN", "Framing", -5,
                 "X-Frame-Options has an unusual value: {}".format(xfo), XFO_FIX)]
    return [("WARN", "Framing", -10,
             "No X-Frame-Options and no CSP frame-ancestors: clickjacking possible",
             XFO_FIX)]


def check_xcto(headers):
    """Check X-Content-Type-Options: nosniff."""
    value = headers.get("x-content-type-options", "").strip().lower()
    if value == "nosniff":
        return [("PASS", "MIME", 0, "X-Content-Type-Options: nosniff", None)]
    if value:
        return [("FAIL", "MIME", -10,
                 "X-Content-Type-Options has wrong value: {}".format(value), XCTO_FIX)]
    return [("FAIL", "MIME", -10, "X-Content-Type-Options missing", XCTO_FIX)]


def check_referrer_policy(headers):
    """Check Referrer-Policy presence."""
    value = headers.get("referrer-policy")
    if value:
        return [("PASS", "Referrer", 0,
                 "Referrer-Policy: {}".format(value), None)]
    return [("WARN", "Referrer", -5, "Referrer-Policy missing", REFERRER_FIX)]


def check_permissions_policy(headers):
    """Check Permissions-Policy presence."""
    value = headers.get("permissions-policy")
    if value:
        return [("PASS", "Permissions", 0,
                 "Permissions-Policy: {}".format(trim(value)), None)]
    return [("WARN", "Permissions", -5, "Permissions-Policy missing", PERMISSIONS_FIX)]


def trim(value, limit=90):
    """Shorten a header value for display."""
    value = value.strip()
    if len(value) > limit:
        return value[:limit] + "..."
    return value


def grade(score):
    """Map a numeric score to a letter grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def analyze(final_url, headers):
    """Run all checks. Returns (findings, score, letter)."""
    findings = []
    findings.extend(check_hsts(headers))
    findings.extend(check_csp(headers))
    findings.extend(check_framing(headers))
    findings.extend(check_xcto(headers))
    findings.extend(check_referrer_policy(headers))
    findings.extend(check_permissions_policy(headers))
    score = max(0, 100 + sum(points for _, _, points, _, _ in findings))
    return findings, score, grade(score)


def render_report(url, final_url, status, redirect_chain, findings, score, letter):
    """Build the plain-text report."""
    lines = []
    lines.append("pentrix-headers v{} scan report".format(VERSION))
    lines.append("=" * 60)
    lines.append("Target:      {}".format(url))
    if final_url != url:
        lines.append("Final URL:   {}".format(final_url))
    for src, dst in redirect_chain:
        lines.append("Redirected:  {} -> {}".format(src, dst))
    lines.append("HTTP status: {}".format(status))
    lines.append("")
    lines.append("{:<6} {:<12} {}".format("RESULT", "CHECK", "DETAIL"))
    lines.append("-" * 60)
    for result, check, points, detail, fix in findings:
        tag = result
        if points:
            tag = "{} ({:+d})".format(result, points)
        lines.append("{:<6} {:<12} {}".format(tag, check, detail))
        if fix:
            lines.append("       -> {}".format(fix))
    lines.append("")
    lines.append("Score: {}/100".format(score))
    lines.append("Grade: {}".format(letter))
    lines.append("=" * 60)
    return "\n".join(lines) + "\n"


def build_parser():
    """Build the argparse parser with full help text."""
    parser = argparse.ArgumentParser(
        prog="headers.py",
        description=(
            "Scan a website's HTTP security headers and grade them A-F. "
            "Sends a single GET request. Checks Strict-Transport-Security, "
            "Content-Security-Policy, X-Frame-Options (or CSP frame-ancestors), "
            "X-Content-Type-Options, Referrer-Policy and Permissions-Policy, "
            "then prints a score out of 100, a letter grade, and one-line fix "
            "advice for every failed or warned check."
        ),
        epilog=(
            "examples:\n"
            "  python3 headers.py https://example.com\n"
            "  python3 headers.py example.com --timeout 5\n"
            "  python3 headers.py https://github.com -o report.txt\n"
            "  python3 headers.py https://example.com --no-redirect\n"
            "\n"
            "grades: A (>=90)  B (>=80)  C (>=70)  D (>=60)  F (<60)\n"
            "exit codes: 0 scan completed, 1 network or fetch error, "
            "2 bad arguments"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", help="URL to scan (scheme optional, https assumed)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--no-redirect",
        action="store_true",
        help="do not follow HTTP redirects; report the redirect target instead",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="write the report to FILE as well as printing it",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="pentrix-headers {}".format(VERSION),
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    url = normalize_url(args.url)
    if url is None:
        parser.error("no URL provided")

    try:
        final_url, headers, status, redirect_chain = fetch(
            url, args.timeout, follow_redirects=not args.no_redirect
        )
    except SystemExitRedirect as exc:
        print("Redirect refused (--no-redirect): {} -> {}".format(url, exc.location),
              file=sys.stderr)
        return 1
    except urllib.error.HTTPError as exc:
        print("HTTP error: {} {}".format(exc.code, exc.reason), file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        reason = exc.reason
        if hasattr(reason, "strerror") and reason.strerror:
            reason = reason.strerror
        print("Connection failed for {}: {}".format(url, reason), file=sys.stderr)
        print("Hint: check the URL, your network, and DNS.", file=sys.stderr)
        return 1
    except TimeoutError:
        print("Request to {} timed out after {}s.".format(url, args.timeout),
              file=sys.stderr)
        return 1
    except Exception as exc:  # socket.timeout and friends
        print("Request to {} failed: {}".format(url, exc), file=sys.stderr)
        return 1

    findings, score, letter = analyze(final_url, headers)
    report = render_report(url, final_url, status, redirect_chain, findings, score, letter)

    print(report, end="")
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
            print("Report written to {}".format(args.output))
        except OSError as exc:
            print("Could not write {}: {}".format(args.output, exc), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
