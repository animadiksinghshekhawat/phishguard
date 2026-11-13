import json
import re
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import joblib
from flask import Flask, request, render_template, jsonify

from feature_extractor import extract_features, FEATURES

BASE = Path(__file__).resolve().parent
MODEL_DIR = BASE / "models"

app = Flask(__name__)

# ── Load model artefacts ─────────────────────────────────────────────────────
BEST_MODEL_PATH = MODEL_DIR / "best_model.joblib"
COMPARISON_PATH = MODEL_DIR / "model_comparison.json"

model      = joblib.load(BEST_MODEL_PATH)
comparison = json.loads(COMPARISON_PATH.read_text(encoding="utf-8"))
BEST_MODEL_NAME  = comparison["best_model"]
PHISHING_LABEL   = comparison.get("phishing_label", -1)
LEGITIMATE_LABEL = comparison.get("legitimate_label", 1)


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize(raw: str) -> str:
    raw = (raw or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", raw):
        raw = "https://" + raw
    return raw


def domain_is_ip(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


# ── Core ML + feature extraction ─────────────────────────────────────────────

def ml_predict(url: str):
    """
    Run feature extraction (all 30 features, with live network calls) and
    return (predicted_label, phishing_probability, feature_flags, page_meta).
    """
    values, flags, page_meta = extract_features(url, enable_network=True)
    row = pd.DataFrame([values], columns=FEATURES)

    predicted  = int(model.predict(row)[0])
    proba      = model.predict_proba(row)[0]
    classes    = list(model.classes_)
    prob_map   = {int(c): float(p) for c, p in zip(classes, proba)}
    phishing_p = prob_map.get(PHISHING_LABEL, 0.0)

    return predicted, phishing_p, flags, page_meta


# ── Heuristic explanation generator ──────────────────────────────────────────

_SUSPICIOUS_WORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "security", "account", "update", "confirm", "password", "wallet",
    "banking", "unlock", "authenticate", "credential", "payment",
]
_OFFICIAL_BRANDS = {
    "paypal":    "paypal.com",
    "google":    "google.com",
    "microsoft": "microsoft.com",
    "apple":     "apple.com",
    "amazon":    "amazon.com",
    "facebook":  "facebook.com",
    "instagram": "instagram.com",
    "netflix":   "netflix.com",
    "chase":     "chase.com",
    "wellsfargo":"wellsfargo.com",
    "citibank":  "citibank.com",
}


def heuristic_reasons(raw_url: str, flags: dict) -> list[str]:
    """Generate human-readable explanations from both URL signals and ML flags."""
    url  = normalize(raw_url)
    p    = urlparse(url)
    host = (p.hostname or "").lower().rstrip(".")
    path_text = (p.path + "?" + p.query).lower()
    reasons   = []

    # ── URL-structure reasons ─────────────────────────────────────────────────
    if flags.get("UsingIP") == -1:
        reasons.append("The URL uses a raw IP address instead of a domain name.")
    if flags.get("LongURL") == -1:
        reasons.append("The URL is unusually long (≥75 characters).")
    if flags.get("ShortURL") == -1:
        reasons.append("The URL uses a known link-shortening service, hiding the real destination.")
    if flags.get("Symbol@") == -1:
        reasons.append("The URL contains '@', which can redirect browsers to a different host.")
    if flags.get("Redirecting//") == -1:
        reasons.append("The URL path contains an unusual double-slash redirect pattern.")
    if flags.get("PrefixSuffix-") == -1:
        reasons.append("The domain contains a hyphen — common in look-alike / typosquatting domains.")
    if flags.get("SubDomains") == -1:
        reasons.append("The domain has an unusually large number of subdomain levels.")
    if flags.get("HTTPS") == -1:
        reasons.append("The URL does not use HTTPS (unencrypted connection).")
    if flags.get("NonStdPort") == -1:
        reasons.append("The URL uses a non-standard port (not 80 or 443).")
    if flags.get("HTTPSDomainURL") == -1:
        reasons.append("The domain name itself contains 'https', a common deception tactic.")

    # ── WHOIS / domain-age reasons ────────────────────────────────────────────
    if flags.get("AgeofDomain") == -1:
        reasons.append("The domain was registered very recently (under 6 months ago).")
    if flags.get("DomainRegLen") == -1:
        reasons.append("The domain registration is short-term (under 1 year), typical of throwaway phishing domains.")
    if flags.get("DNSRecording") == -1:
        reasons.append("The domain has no valid DNS records — it may not exist or be a placeholder.")

    # ── Reputation reasons ────────────────────────────────────────────────────
    if flags.get("StatsReport") == -1:
        reasons.append("⚠️ The domain is listed in SURBL — a known spam / phishing blacklist.")
    if flags.get("WebsiteTraffic") == -1:
        reasons.append("The domain has very low or no detectable web traffic.")
    if flags.get("PageRank") == -1:
        reasons.append("The domain has a very low or zero PageRank, suggesting it is new or unknown.")
    if flags.get("LinksPointingToPage") == -1:
        reasons.append("No other websites appear to link to this domain (zero backlinks).")

    # ── Page-content reasons ──────────────────────────────────────────────────
    if flags.get("ServerFormHandler") == -1:
        reasons.append("The page contains forms that submit credentials to an external or empty destination.")
    if flags.get("IframeRedirection") == -1:
        reasons.append("The page uses hidden iframes — a classic phishing content-injection technique.")
    if flags.get("DisableRightClick") == -1:
        reasons.append("The page tries to disable right-click, preventing users from inspecting the source.")
    if flags.get("UsingPopupWindow") == -1:
        reasons.append("The page opens popup windows — often used to harvest credentials.")
    if flags.get("StatusBarCust") == -1:
        reasons.append("The page manipulates the browser status bar to display false URLs.")
    if flags.get("WebsiteForwarding") == -1:
        reasons.append("The URL involves an excessive number of redirections (≥4 hops).")
    if flags.get("RequestURL") == -1:
        reasons.append("Most images and resources on the page are loaded from external domains.")
    if flags.get("AnchorURL") == -1:
        reasons.append("Most links on the page point to external domains.")
    if flags.get("Favicon") == -1:
        reasons.append("The page loads its favicon from an external domain — a brand-impersonation signal.")

    # ── Keyword & brand-impersonation reasons ─────────────────────────────────
    if any(w in host for w in _SUSPICIOUS_WORDS) or any(w in path_text for w in _SUSPICIOUS_WORDS):
        reasons.append("The URL contains account / security keywords commonly seen in phishing links.")
    for brand, official in _OFFICIAL_BRANDS.items():
        if brand in host and host != official and not host.endswith("." + official):
            reasons.append(f"The domain may be impersonating the brand '{brand}' (official: {official}).")
            break

    return reasons


# ── Guardrail scoring (high-confidence deterministic rules) ───────────────────

def guardrail_score(raw_url: str, flags: dict) -> float:
    """
    Deterministic risk score (0–100) based on high-confidence signals.
    Prevents obvious phishing from slipping through when the ML model is
    uncertain (e.g. due to neutral values for page-content features).
    """
    score = 0
    url   = normalize(raw_url)
    p     = urlparse(url)
    host  = (p.hostname or "").lower().rstrip(".")
    text  = (p.path + "?" + p.query).lower()

    # URL structure
    if flags.get("UsingIP")       == -1: score += 55
    if flags.get("Symbol@")       == -1: score += 55
    if flags.get("ShortURL")      == -1: score += 35
    if flags.get("Redirecting//") == -1: score += 35
    if flags.get("LongURL")       == -1: score += 25
    if flags.get("SubDomains")    == -1: score += 25
    if flags.get("HTTPS")         == -1: score += 12

    # Domain health
    if flags.get("DNSRecording")   == -1: score += 40
    if flags.get("AgeofDomain")    == -1: score += 20
    if flags.get("DomainRegLen")   == -1: score += 15

    # Reputation blacklists
    if flags.get("StatsReport")    == -1: score += 60   # SURBL-listed = very high risk

    # Page-content signals
    if flags.get("ServerFormHandler") == -1: score += 20
    if flags.get("IframeRedirection") == -1: score += 15
    if flags.get("DisableRightClick") == -1: score += 10
    if flags.get("WebsiteForwarding") == -1: score += 15
    if flags.get("AnchorURL")         == -1: score += 15

    # Keyword matching
    _sus = ["login","signin","verify","verification","account","password",
            "secure","confirm","banking","wallet","payment","unlock"]
    if any(w in host for w in _sus): score += 20
    if any(w in text for w in _sus): score += 15

    # Brand impersonation
    for brand, official in _OFFICIAL_BRANDS.items():
        if brand in host and host != official and not host.endswith("." + official):
            score += 55
            break

    return min(100.0, float(score))


# ── Main analysis function ────────────────────────────────────────────────────

def analyze(raw: str) -> dict:
    url  = normalize(raw)
    p    = urlparse(url)
    host = (p.hostname or "").lower().rstrip(".")

    if not host:
        return {
            "prediction":    "PHISHING",
            "score":         100,
            "reasons":       ["Invalid or missing domain."],
            "features":      {},
            "flags":         {},
            "model":         BEST_MODEL_NAME,
            "model_accuracy": comparison["results"][BEST_MODEL_NAME]["accuracy"] * 100,
            "models":        comparison["results"],
        }

    predicted, phishing_p, flags, page_meta = ml_predict(url)

    reasons = heuristic_reasons(url, flags)

    # Supplement reasons from live page data
    redirects = page_meta.get("redirects", "Unknown")
    if isinstance(redirects, int) and redirects >= 3:
        reasons.append("The URL redirects through several intermediate destinations.")
    pw_fields = page_meta.get("password_fields", "Unknown")
    if isinstance(pw_fields, int) and pw_fields > 0:
        reasons.append("The page contains a password input field.")
    iframes = page_meta.get("iframes", "Unknown")
    if isinstance(iframes, int) and iframes >= 3:
        reasons.append("The page contains multiple iframes.")

    if any(x in (page_meta.get("html_low", "") or "") for x in [
        "verify your account", "confirm your account", "suspended account", "enter your password"
    ]):
        reasons.append("The page contains common phishing-style account prompts.")

    ml_score       = phishing_p * 100
    guardrail      = guardrail_score(url, flags)
    score          = round(max(ml_score, guardrail), 2)
    prediction     = "PHISHING" if score >= 50 else "LEGITIMATE"

    if not reasons:
        reasons = ["No major suspicious indicators detected."]

    return {
        "prediction":    prediction,
        "score":         score,
        "phishing_probability": score,
        "reasons":       list(dict.fromkeys(reasons)),
        "features":      page_meta,
        "flags":         flags,          # full 30-feature detail for display
        "model":         BEST_MODEL_NAME,
        "model_accuracy": round(comparison["results"][BEST_MODEL_NAME]["accuracy"] * 100, 2),
        "models":        comparison["results"],
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    url    = ""
    if request.method == "POST":
        url    = request.form.get("url", "")
        result = analyze(url)
    return render_template(
        "index.html",
        result=result,
        url=url,
        best_model=BEST_MODEL_NAME,
        model_results=comparison["results"],
    )


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/api/check", methods=["POST", "OPTIONS"])
@app.route("/api/predict", methods=["POST", "OPTIONS"])
def api_check():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json(silent=True) or {}
    return jsonify(analyze(data.get("url", "")))


@app.route("/api/models", methods=["GET"])
def api_models():
    return jsonify({
        "best_model": BEST_MODEL_NAME,
        "results":    comparison["results"],
    })


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
