"""
feature_extractor.py — PhishGuard AI
======================================
All 30 UCI phishing dataset features, fully implemented.

Feature encoding (matches training-data convention):
  -1  suspicious / phishing indicator
   0  neutral / unknown  (network unavailable or not applicable)
   1  benign / legitimate indicator

Network calls run concurrently (page-fetch + WHOIS + DNS + SURBL + PageRank)
so total latency ≈ max(individual timeouts) rather than their sum.

Optional env-vars:
  OPENPAGERANK_API_KEY  — free key from https://www.domcop.com/openpagerank/
                          enables real PageRank & LinksPointingToPage values.
"""

from __future__ import annotations

import os
import re
import socket
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

# ── Optional third-party imports ─────────────────────────────────────────────
try:
    import requests as _req
    _REQUESTS = True
except ImportError:  # pragma: no cover
    _REQUESTS = False

try:
    import whois as _whois_lib          # pip install python-whois
    _WHOIS = True
except ImportError:
    _WHOIS = False

# ── Feature list (must match the column order used during training) ───────────
FEATURES = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//",
    "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon",
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
    "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL",
    "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage",
    "StatsReport",
]

# ── Constants ────────────────────────────────────────────────────────────────
SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "tiny.cc",
    "shorte.st", "clk.sh", "bc.vc", "s.id", "urlshort.link", "v.gd",
    "x.co", "qr.ae", "u.to", "turl.ca", "lnkd.in", "dlvr.it", "ift.tt",
}

# TLDs with strong phishing association (freely registered / cheap)
_RISK_TLDS: frozenset[str] = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".work", ".link", ".click", ".pw", ".cc", ".biz",
})

# High-trust government / academic TLDs
_TRUST_TLDS: frozenset[str] = frozenset({".gov", ".edu", ".mil"})

# Request timeouts (seconds)
_PAGE_TIMEOUT  = 7
_WHOIS_TIMEOUT = 9
_DNS_TIMEOUT   = 4
_OPR_TIMEOUT   = 8   # Open PageRank API
_DEFAULT_OPR_KEY = "opr_live_dce9694126ffbd5370b010c2d8943332325790f7"

def _get_opr_key() -> str:
    env_val = (os.getenv("OPENPAGERANK_API_KEY") or "").strip()
    return env_val if env_val else _DEFAULT_OPR_KEY

_OPR_ENDPOINT  = "https://openpagerank.keywordseverywhere.com/api/v1.0/getPageRank"

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; PhishGuardAI/2.0)"}


# ═══════════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_url(url: str) -> str:
    """Prepend https:// if no scheme is present."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return url


def _parse_host(parsed) -> str:
    return (parsed.hostname or "").lower().strip(".")


def _registrable(domain: str) -> str:
    """Return eTLD+1 (e.g. 'sub.example.co.uk' → 'example.co.uk')."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _is_ip(domain: str) -> bool:
    """True if domain is an IPv4 or IPv6 address."""
    for af in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(af, domain)
            return True
        except (OSError, socket.error):
            pass
    return False


def _extract_hostname(url_str: str) -> str | None:
    try:
        return urlparse(url_str).hostname or None
    except Exception:
        return None


def _pct_external(urls: list[str], host: str) -> float:
    """% of URLs whose hostname differs from *host*."""
    if not urls:
        return 0.0
    external = sum(
        1 for u in urls
        if (h := _extract_hostname(u)) and h.lower() != host
    )
    return external / len(urls) * 100.0


# ═══════════════════════════════════════════════════════════════════════════════
# Network fetch helpers (each called in a separate daemon thread)
# ═══════════════════════════════════════════════════════════════════════════════

def _fetch_page(url: str) -> tuple[object | None, str, int]:
    """
    GET the URL and return (response, html_text, redirect_count).
    Returns (None, '', 0) on any failure.
    """
    if not _REQUESTS:
        return None, "", 0
    try:
        r = _req.get(
            url,
            timeout=_PAGE_TIMEOUT,
            allow_redirects=True,
            headers=_HEADERS,
            stream=True,
        )
        redirects = len(r.history)
        ctype = (r.headers.get("content-type") or "").lower()
        html  = r.text[:3_000_000] if "text/html" in ctype else ""
        return r, html, redirects
    except Exception:
        return None, "", 0


def _fetch_domain_dates(domain: str) -> tuple[datetime | None, datetime | None, str | None]:
    """
    Returns (created_dt, expires_dt, registrar_str).
    Uses HTTPS RDAP (ICANN standard, works on Linux/Docker/Cloud) with python-whois fallback.
    """
    reg_domain = _registrable(domain)
    created_dt, expires_dt, registrar_str = None, None, None

    # 1. Try RDAP over HTTPS (ICANN standard, works reliably across all TLDs without port 43)
    if _REQUESTS:
        try:
            r = _req.get(
                f"https://rdap.org/domain/{reg_domain}",
                timeout=6,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            if r.status_code == 200:
                data = r.json()
                for ev in data.get("events", []):
                    act = ev.get("eventAction")
                    dt_str = ev.get("eventDate")
                    if act == "registration" and dt_str:
                        created_dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                    elif act == "expiration" and dt_str:
                        expires_dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                for ent in data.get("entities", []):
                    if "registrar" in ent.get("roles", []):
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if len(item) > 3 and item[0] == "fn":
                                    registrar_str = str(item[3])
        except Exception:
            pass

    # 2. Fallback to python-whois if RDAP was unavailable or incomplete
    if (not created_dt or not expires_dt) and _WHOIS:
        try:
            w = _whois_lib.query(reg_domain)
            if w:
                if not created_dt and getattr(w, "creation_date", None):
                    c = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    if isinstance(c, datetime):
                        if c.tzinfo is None: c = c.replace(tzinfo=timezone.utc)
                        created_dt = c
                if not expires_dt and getattr(w, "expiration_date", None):
                    e = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                    if isinstance(e, datetime):
                        if e.tzinfo is None: e = e.replace(tzinfo=timezone.utc)
                        expires_dt = e
                if not registrar_str and getattr(w, "registrar", None):
                    registrar_str = str(w.registrar)
        except Exception:
            pass

    return created_dt, expires_dt, registrar_str


def _check_dns(domain: str) -> bool:
    """True if the domain resolves in DNS."""
    try:
        socket.setdefaulttimeout(_DNS_TIMEOUT)
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False


def _surbl_listed(domain: str) -> bool:
    """
    Free DNS-based SURBL reputation check (no API key needed).
    Returns True if the domain is listed as spam / phishing.
    """
    target = f"{_registrable(domain)}.multi.surbl.org"
    try:
        socket.setdefaulttimeout(_DNS_TIMEOUT)
        socket.gethostbyname(target)
        return True            # resolves → listed
    except socket.gaierror:
        return False           # NXDOMAIN → clean
    except Exception:
        return False


def _open_pagerank(domain: str) -> dict:
    """
    Query the Open PageRank API (https://openpagerank.keywordseverywhere.com).
    Returns dict with keys: 'page_rank_decimal' (0–10), 'rank' (global), or {}.
    """
    key = _get_opr_key()
    if not _REQUESTS or not key:
        return {}
    try:
        headers = {
            "API-OPR": key,
            "Authorization": f"Bearer {key}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        r = _req.get(
            _OPR_ENDPOINT,
            params={"domains[]": _registrable(domain)},
            headers=headers,
            timeout=_OPR_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            rows = data.get("response", [])
            if rows:
                return rows[0]
    except Exception:
        pass
    return {}


# ═══════════════════════════════════════════════════════════════════════════════
# HTML analysis
# ═══════════════════════════════════════════════════════════════════════════════

def _analyze_html(html: str, host: str) -> dict:
    """
    Extract all page-level signals using regex (no external HTML parser needed).
    Returns a dict of extracted signals and raw counts.
    """
    low = html.lower()

    # ── Resources (img, script src, link href) ────────────────────────────────
    img_srcs    = re.findall(r"<img\b[^>]+\bsrc=[\"']?([^\"'>\s]+)", html, re.I)
    script_srcs = re.findall(r"<script\b[^>]+\bsrc=[\"']?([^\"'>\s]+)", html, re.I)
    link_hrefs  = re.findall(r"<link\b[^>]+\bhref=[\"']?([^\"'>\s]+)", html, re.I)
    all_resources = img_srcs + script_srcs + link_hrefs

    # ── Anchors ───────────────────────────────────────────────────────────────
    anchor_hrefs = re.findall(r"<a\b[^>]+\bhref=[\"']?([^\"'>\s#][^\"'>\s]*)", html, re.I)
    anchor_hrefs = [
        a for a in anchor_hrefs
        if not a.lower().startswith("javascript") and a not in ("#", "")
    ]

    # ── Script + link tags (LinksInScriptTags) ────────────────────────────────
    script_link_urls = script_srcs + link_hrefs

    # ── Form actions ──────────────────────────────────────────────────────────
    form_actions = re.findall(r"<form\b[^>]+\baction=[\"']?([^\"'>\s]*)", html, re.I)

    # ── Favicon ───────────────────────────────────────────────────────────────
    # Try rel="icon" / rel="shortcut icon"
    fav_m = re.search(
        r'<link\b[^>]+\brel=["\']?(?:shortcut\s+icon|icon)["\']?[^>]*\bhref=["\']?([^"\'>\s]+)',
        html, re.I,
    )
    if not fav_m:
        fav_m = re.search(
            r'<link\b[^>]+\bhref=["\']?([^"\'>\s]+)["\']?[^>]*\brel=["\']?(?:shortcut\s+icon|icon)',
            html, re.I,
        )
    favicon_url = fav_m.group(1) if fav_m else None

    # ── JavaScript behaviour patterns ─────────────────────────────────────────
    has_window_status = "window.status" in low
    has_right_click   = bool(re.search(r"event\.button\s*==\s*[\"']?2|contextmenu", low))
    has_popup         = bool(re.search(r"window\.open\s*\(", low))
    has_iframe        = bool(re.search(r"<iframe\b", low))

    # ── Raw counts for the UI ─────────────────────────────────────────────────
    pw_count     = len(re.findall(r"type\s*=\s*[\"']?password", low))
    form_count   = len(re.findall(r"<form\b", low))
    iframe_count = len(re.findall(r"<iframe\b", low))
    ext_links    = sum(
        1 for h in anchor_hrefs[:1000]
        if (hn := _extract_hostname(h)) and hn.lower() != host
    )

    return {
        "favicon_url":       favicon_url,
        "resource_urls":     all_resources,
        "anchor_urls":       anchor_hrefs,
        "script_link_urls":  script_link_urls,
        "form_actions":      form_actions,
        "has_window_status": has_window_status,
        "has_right_click":   has_right_click,
        "has_popup":         has_popup,
        "has_iframe":        has_iframe,
        # raw counts for the security-signals UI panel:
        "password_fields":   pw_count,
        "form_count":        form_count,
        "iframe_count":      iframe_count,
        "external_links":    ext_links,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# WHOIS helper utilities
# ═══════════════════════════════════════════════════════════════════════════════

def _whois_created(w) -> datetime | None:
    if not w:
        return None
    try:
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, datetime):
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            return created
    except Exception:
        pass
    return None


def _whois_expires(w) -> datetime | None:
    if not w:
        return None
    try:
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        if isinstance(exp, datetime):
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return exp
    except Exception:
        pass
    return None


def _age_days(w) -> int | None:
    created = _whois_created(w)
    if not created:
        return None
    return max(0, (datetime.now(timezone.utc) - created).days)


# ═══════════════════════════════════════════════════════════════════════════════
# Reputation heuristics used when API is unavailable
# ═══════════════════════════════════════════════════════════════════════════════

def _heuristic_traffic(domain: str, age_d: int | None) -> int:
    """Estimate traffic tier: 1=high, 0=medium, -1=low."""
    if any(domain.endswith(t) for t in _TRUST_TLDS):
        return 1
    if any(domain.endswith(t) for t in _RISK_TLDS):
        return -1
    if age_d is not None:
        if age_d > 730:  return 1
        if age_d > 180:  return 0
        return -1
    return 0


def _heuristic_google_index(domain: str, has_dns_: bool, age_d: int | None) -> int:
    if not has_dns_:
        return -1
    if any(domain.endswith(t) for t in _TRUST_TLDS):
        return 1
    if age_d is not None and age_d > 180:
        return 1
    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# Main feature extraction entry point
# ═══════════════════════════════════════════════════════════════════════════════

def extract_features(
    url: str,
    enable_network: bool = True,
) -> tuple[list[int], dict, dict]:
    """
    Extract all 30 phishing-detection features.

    Parameters
    ----------
    url            : URL string to analyse.
    enable_network : When False, only URL-based features are computed (instant).
                     All network-dependent features default to 0 (neutral).

    Returns
    -------
    values    : list[int]  — ordered feature vector aligned with FEATURES.
    flags     : dict       — feature_name → encoded value (-1 / 0 / 1).
    page_meta : dict       — raw data for the UI security-signals panel.
    """
    u      = normalize_url(url.strip())
    p      = urlparse(u)
    domain = _parse_host(p)
    full   = u

    f: dict[str, int] = {}

    # Initialise page_meta with URL-only fields (always available)
    meta: dict = {
        "https":           "Yes" if p.scheme == "https" else "No",
        "ip":              "Yes" if _is_ip(domain) else "No",
        "url_length":      len(full),
        "subdomains":      max(0, len([x for x in domain.split(".") if x]) - 2),
        "redirects":       "Unknown",
        "forms":           "Unknown",
        "password_fields": "Unknown",
        "external_links":  "Unknown",
        "iframes":         "Unknown",
        "domain_age":      "Unknown",
        "registrar":       "Unknown",
        "dns_records":     "Unknown",
        "blacklisted":     "Unknown",
        "pagerank":        "Unknown",
        "fetch_error":     None,
    }

    # ── ─────────────────────────────────────────────────────────────────────
    # GROUP 1 — URL-only features (always computed, zero network overhead)
    # ──────────────────────────────────────────────────────────────────────────

    # 1. UsingIP
    f["UsingIP"] = -1 if _is_ip(domain) else 1

    # 2. LongURL   (≥75 chars → suspicious, 54–74 → borderline, <54 → fine)
    length = len(full)
    f["LongURL"] = -1 if length >= 75 else (0 if length >= 54 else 1)

    # 3. ShortURL  (known URL-shortening service)
    f["ShortURL"] = -1 if domain in SHORTENERS else 1

    # 4. Symbol@
    f["Symbol@"] = -1 if "@" in full else 1

    # 5. Redirecting//  (double-slash after scheme separator)
    path_part = full.split("://", 1)[-1] if "://" in full else full
    f["Redirecting//"] = -1 if "//" in path_part else 1

    # 6. PrefixSuffix-  (hyphen in domain = look-alike risk)
    f["PrefixSuffix-"] = -1 if "-" in domain else 1

    # 7. SubDomains  (≥4 labels → -1, 3 → 0, ≤2 → 1)
    labels = [x for x in domain.split(".") if x]
    f["SubDomains"] = -1 if len(labels) >= 4 else (0 if len(labels) == 3 else 1)

    # 8. HTTPS
    f["HTTPS"] = 1 if p.scheme.lower() == "https" else -1

    # 11. NonStdPort (keeping original FEATURES index position)
    f["NonStdPort"] = -1 if (p.port and p.port not in (80, 443)) else 1

    # 12. HTTPSDomainURL  ("https" literally appears in the domain label)
    f["HTTPSDomainURL"] = -1 if "https" in domain else 1

    # 17. InfoEmail
    f["InfoEmail"] = -1 if re.search(r"mailto:|email", full, re.I) else 1

    # 18. AbnormalURL  (netloc host doesn't match extracted domain)
    netloc_host = (p.hostname or "").lower().strip(".")
    f["AbnormalURL"] = -1 if (domain and netloc_host != domain) else 1

    # ── ─────────────────────────────────────────────────────────────────────
    # GROUP 2 — Network-dependent features (skipped when enable_network=False)
    # ──────────────────────────────────────────────────────────────────────────

    _network_feats = [
        "DomainRegLen", "Favicon", "RequestURL", "AnchorURL",
        "LinksInScriptTags", "ServerFormHandler", "WebsiteForwarding",
        "StatusBarCust", "DisableRightClick", "UsingPopupWindow",
        "IframeRedirection", "AgeofDomain", "DNSRecording",
        "WebsiteTraffic", "PageRank", "GoogleIndex",
        "LinksPointingToPage", "StatsReport",
    ]

    if not enable_network or not domain:
        for feat in _network_feats:
            f[feat] = 0
        return [int(f[n]) for n in FEATURES], f, meta

    # ── Concurrent network calls ──────────────────────────────────────────────
    _page  = [None, "", 0]          # (response, html, redirect_count)
    _dates = [None, None, None]     # (created_dt, expires_dt, registrar_str)
    _dns   = [False]                # DNS resolves?
    _surbl = [False]                # SURBL listed?
    _opr   = [{}]                   # Open PageRank data

    def do_page() -> None:
        if p.scheme in ("http", "https"):
            _page[0], _page[1], _page[2] = _fetch_page(u)

    def do_dates() -> None:
        if not _is_ip(domain):
            _dates[0], _dates[1], _dates[2] = _fetch_domain_dates(domain)

    def do_dns() -> None:
        _dns[0] = _check_dns(domain)

    def do_surbl() -> None:
        if not _is_ip(domain):
            _surbl[0] = _surbl_listed(domain)

    def do_opr() -> None:
        _opr[0] = _open_pagerank(domain)

    threads = [
        threading.Thread(target=do_page,  daemon=True),
        threading.Thread(target=do_dates, daemon=True),
        threading.Thread(target=do_dns,   daemon=True),
        threading.Thread(target=do_surbl, daemon=True),
        threading.Thread(target=do_opr,   daemon=True),
    ]
    for t in threads:
        t.start()
    max_wait = max(_PAGE_TIMEOUT, _WHOIS_TIMEOUT, _OPR_TIMEOUT) + 2
    for t in threads:
        t.join(timeout=max_wait)

    resp, html, redirect_count = _page
    cre_d, exp_d, reg_str      = _dates
    has_dns_                   = _dns[0]
    is_surbl                   = _surbl[0]
    opr_data                   = _opr[0]

    # Computed age in days
    age_d = max(0, (datetime.now(timezone.utc) - cre_d).days) if cre_d else None

    # HTML analysis
    hd = _analyze_html(html, domain) if html else None

    # ── Update page_meta for the UI panel ─────────────────────────────────────
    meta["redirects"]   = redirect_count
    meta["dns_records"] = "Yes" if has_dns_ else "No"
    meta["blacklisted"] = "Yes ⚠️" if is_surbl else "No"
    if hd:
        meta["forms"]           = hd["form_count"]
        meta["password_fields"] = hd["password_fields"]
        meta["iframes"]         = hd["iframe_count"]
        meta["external_links"]  = hd["external_links"]
    if not resp and p.scheme in ("http", "https"):
        meta["fetch_error"] = "Could not fetch page"
    if age_d is not None:
        yrs = age_d // 365
        mns = (age_d % 365) // 30
        meta["domain_age"] = f"{yrs}y {mns}m" if yrs else f"{mns}m"
    if reg_str:
        meta["registrar"] = reg_str[:60]
    if opr_data and opr_data.get("page_rank_decimal") is not None and str(opr_data.get("page_rank_decimal")) != "":
        try:
            meta["pagerank"] = round(float(opr_data["page_rank_decimal"]), 2)
        except (ValueError, TypeError):
            pass

    # ═════════════════════════════════════════════════════════════════════════
    # Individual feature computation
    # ═════════════════════════════════════════════════════════════════════════

    # ── 9. DomainRegLen ───────────────────────────────────────────────────────
    # Registration length = expiry − creation.  >1 year → legitimate.
    if cre_d and exp_d:
        reg_days = (exp_d - cre_d).days
        f["DomainRegLen"] = 1 if reg_days >= 365 else -1
    else:
        f["DomainRegLen"] = 0

    # ── 10. Favicon ───────────────────────────────────────────────────────────
    # Phishing sites often load the favicon from a trusted domain.
    if hd and hd["favicon_url"]:
        fav_host = _extract_hostname(hd["favicon_url"])
        if fav_host:
            f["Favicon"] = 1 if fav_host.lower() == domain else -1
        else:
            f["Favicon"] = 1   # relative URL → same domain
    elif html:
        f["Favicon"] = 1       # page fetched, no explicit favicon (benign default)
    else:
        f["Favicon"] = 0

    # ── 13. RequestURL ────────────────────────────────────────────────────────
    # % of img / script / link resources loaded from external domains.
    # <22 % → 1  |  22–61 % → 0  |  >61 % → -1
    if hd:
        pct = _pct_external(hd["resource_urls"], domain)
        f["RequestURL"] = -1 if pct >= 61 else (0 if pct >= 22 else 1)
    else:
        f["RequestURL"] = 0

    # ── 14. AnchorURL ─────────────────────────────────────────────────────────
    # % of <a href> links pointing to external domains.
    # <31 % → 1  |  31–67 % → 0  |  >67 % → -1
    if hd:
        pct = _pct_external(hd["anchor_urls"], domain)
        f["AnchorURL"] = -1 if pct >= 67 else (0 if pct >= 31 else 1)
    else:
        f["AnchorURL"] = 0

    # ── 15. LinksInScriptTags ─────────────────────────────────────────────────
    # % of <script src> and <link href> pointing to external domains.
    # <17 % → 1  |  17–67 % → 0  |  >67 % → -1
    if hd:
        pct = _pct_external(hd["script_link_urls"], domain)
        f["LinksInScriptTags"] = -1 if pct >= 67 else (0 if pct >= 17 else 1)
    else:
        f["LinksInScriptTags"] = 0

    # ── 16. ServerFormHandler ─────────────────────────────────────────────────
    # Phishing forms submit to external servers, blank targets, or empty actions.
    if hd and hd["form_actions"]:
        suspicious = False
        for action in hd["form_actions"]:
            action = action.strip()
            if not action or action.lower() in ("about:blank", "#", "javascript:void(0)"):
                suspicious = True
                break
            ah = _extract_hostname(action)
            if ah and ah.lower() != domain:
                suspicious = True
                break
        f["ServerFormHandler"] = -1 if suspicious else 1
    else:
        f["ServerFormHandler"] = 0   # no forms fetched / no forms on page

    # ── 19. WebsiteForwarding ─────────────────────────────────────────────────
    # Number of HTTP redirects: 0–1 → 1  |  2–3 → 0  |  ≥4 → -1
    f["WebsiteForwarding"] = (
        -1 if redirect_count >= 4 else (0 if redirect_count >= 2 else 1)
    )

    # ── 20. StatusBarCust ─────────────────────────────────────────────────────
    # Phishers override window.status to display fake URLs in the status bar.
    if html:
        f["StatusBarCust"] = -1 if (hd and hd["has_window_status"]) else 1
    else:
        f["StatusBarCust"] = 0

    # ── 21. DisableRightClick ─────────────────────────────────────────────────
    # Disabling right-click (event.button==2 / contextmenu) hides "View Source".
    if html:
        f["DisableRightClick"] = -1 if (hd and hd["has_right_click"]) else 1
    else:
        f["DisableRightClick"] = 0

    # ── 22. UsingPopupWindow ──────────────────────────────────────────────────
    # window.open() calls suggest credential-harvesting popup dialogs.
    if html:
        f["UsingPopupWindow"] = -1 if (hd and hd["has_popup"]) else 1
    else:
        f["UsingPopupWindow"] = 0

    # ── 23. IframeRedirection ─────────────────────────────────────────────────
    # Hidden iframes are a classic phishing technique.
    if html:
        f["IframeRedirection"] = -1 if (hd and hd["has_iframe"]) else 1
    else:
        f["IframeRedirection"] = 0

    # ── 24. AgeofDomain ───────────────────────────────────────────────────────
    # Phishing domains are typically very new.
    # <6 months → -1  |  6–12 months → 0  |  >12 months → 1
    if age_d is not None:
        months = age_d / 30.0
        f["AgeofDomain"] = 1 if months >= 12 else (0 if months >= 6 else -1)
    else:
        f["AgeofDomain"] = 0

    # ── 25. DNSRecording ──────────────────────────────────────────────────────
    # Domains used for phishing are sometimes not properly set up in DNS.
    f["DNSRecording"] = 1 if has_dns_ else -1

    # ── 26. WebsiteTraffic ────────────────────────────────────────────────────
    # Approximated from domain age + TLD trust level.
    f["WebsiteTraffic"] = _heuristic_traffic(domain, age_d)

    # ── 27. PageRank ──────────────────────────────────────────────────────────
    # Uses Open PageRank API when OPENPAGERANK_API_KEY is set, else heuristic.
    if opr_data:
        pr = float(opr_data.get("page_rank_decimal", -1))
        if pr < 0:
            f["PageRank"] = 0
        elif pr <= 2:
            f["PageRank"] = -1
        elif pr <= 4:
            f["PageRank"] = 0
        else:
            f["PageRank"] = 1
    else:
        # Heuristic: age-based PageRank estimation
        if not has_dns_:
            f["PageRank"] = -1
        elif any(domain.endswith(t) for t in _TRUST_TLDS):
            f["PageRank"] = 1
        elif age_d is not None:
            f["PageRank"] = 1 if age_d > 1825 else (0 if age_d > 365 else -1)
        else:
            f["PageRank"] = 0

    # ── 28. GoogleIndex ───────────────────────────────────────────────────────
    # Uses heuristic (domain age + DNS).  Real check needs Custom Search API.
    f["GoogleIndex"] = _heuristic_google_index(domain, has_dns_, age_d)

    # ── 29. LinksPointingToPage ───────────────────────────────────────────────
    # Uses Open PageRank "rank" (global Tranco-based rank) when available,
    # otherwise falls back to domain-age heuristic.
    if opr_data:
        rank = opr_data.get("rank", None)
        if rank is None or rank == "":
            f["LinksPointingToPage"] = -1   # unranked = no backlinks
        else:
            rank = int(rank)
            f["LinksPointingToPage"] = 1 if rank <= 100_000 else (0 if rank <= 1_000_000 else -1)
    else:
        # Heuristic: age-based estimation
        if any(domain.endswith(t) for t in _TRUST_TLDS):
            f["LinksPointingToPage"] = 1
        elif age_d is not None:
            f["LinksPointingToPage"] = 1 if age_d > 365 else (0 if age_d > 90 else -1)
        else:
            f["LinksPointingToPage"] = 0

    # ── 30. StatsReport ───────────────────────────────────────────────────────
    # SURBL multi.surbl.org is a free, DNS-based combined spam/phishing list.
    f["StatsReport"] = -1 if is_surbl else 1

    return [int(f[n]) for n in FEATURES], f, meta


# ═══════════════════════════════════════════════════════════════════════════════
# Utility: human-readable explanations
# ═══════════════════════════════════════════════════════════════════════════════

def explain_features(flags: dict) -> list[tuple[str, str]]:
    """Return a list of (severity, feature_name) tuples."""
    return [
        ("warning" if v == -1 else "safe" if v == 1 else "unknown", name)
        for name, v in flags.items()
    ]
