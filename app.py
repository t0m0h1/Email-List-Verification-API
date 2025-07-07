from flask import Flask, request, jsonify, abort
from functools import wraps
import dns.resolver
import smtplib
from email_validator import validate_email, EmailNotValidError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from typing import Optional, Set

# --- Flask Setup ---
app = Flask(__name__)
limiter = Limiter(app=app, key_func=get_remote_address)

# --- Config ---
VALID_API_KEYS: Set[str] = {"demo-key-123"}
DISPOSABLE_DOMAINS_FILE = "disposable_domains.txt"

def load_disposable_domains() -> Set[str]:
    """Load disposable domains from file, return empty set if file missing."""
    try:
        with open(DISPOSABLE_DOMAINS_FILE) as f:
            domains = {line.strip().lower() for line in f if line.strip()}
        return domains
    except FileNotFoundError:
        app.logger.warning(f"Disposable domains file '{DISPOSABLE_DOMAINS_FILE}' not found.")
        return set()

DISPOSABLE_DOMAINS: Set[str] = load_disposable_domains()

def require_api_key(f):
    """Decorator to require valid API key in header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("x-api-key")
        if not key:
            abort(401, description="Missing API key")
        if key not in VALID_API_KEYS:
            abort(403, description="Invalid API key")
        return f(*args, **kwargs)
    return decorated

def check_syntax(email: str) -> bool:
    """Validate email syntax strictly using email_validator."""
    if not isinstance(email, str) or not email:
        return False
    try:
        validate_email(email)
        return True
    except EmailNotValidError as e:
        app.logger.debug(f"Email syntax invalid: {email} ({e})")
        return False

def domain_exists(domain: str) -> bool:
    """Check if domain resolves to an IP address."""
    if not domain:
        return False
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except Exception:
        return False

def has_mx_record(domain: str) -> bool:
    """Check if domain has MX records."""
    if not domain:
        return False
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except Exception:
        return False

def is_disposable(domain: str) -> bool:
    """Check if domain is in disposable domains list."""
    if not domain:
        return False
    return domain.lower() in DISPOSABLE_DOMAINS

def smtp_check(email: str, domain: str) -> Optional[bool]:
    """Attempt SMTP RCPT TO command to verify mailbox existence.
    Returns True if accepted, False if rejected, None if check not possible."""
    if not email or not domain:
        return None
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if not mx_records:
            return None
        mx_record = str(mx_records[0].exchange).rstrip('.')
        server = smtplib.SMTP(timeout=10)
        server.connect(mx_record)
        server.helo("yourdomain.com")
        server.mail("verify@yourdomain.com")
        code, _ = server.rcpt(email)
        server.quit()
        if code == 250:
            return True
        elif 400 <= code < 500:
            # Temporary rejection - treat as unknown
            return None
        else:
            return False
    except Exception as e:
        app.logger.debug(f"SMTP check error for {email}: {e}")
        return None

@app.route("/verify-email", methods=["POST"])
@require_api_key
@limiter.limit("100/day")
def verify_email():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    email_raw = data.get("email")
    if not isinstance(email_raw, str):
        return jsonify({"error": "Email must be a string"}), 400

    email = email_raw.strip()
    if not email:
        return jsonify({"error": "Email cannot be empty"}), 400

    valid_syntax = check_syntax(email)
    domain = email.split('@')[-1].lower() if valid_syntax and '@' in email else None

    domain_check = domain_exists(domain) if domain else False
    mx_check = has_mx_record(domain) if domain else False
    disposable_check = is_disposable(domain) if domain else False
    smtp_result = smtp_check(email, domain) if domain_check and mx_check else None

    # Determine overall status with clear prioritization
    if disposable_check:
        overall_status = "disposable"
    elif all([valid_syntax, domain_check, mx_check]) and smtp_result is True:
        overall_status = "valid"
    else:
        overall_status = "invalid"

    return jsonify({
        "email": email,
        "valid_syntax": valid_syntax,
        "domain_exists": domain_check,
        "mx_records_found": mx_check,
        "disposable": disposable_check,
        "smtp_check": smtp_result,
        "overall_status": overall_status
    })

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Email Verification API is running."})

if __name__ == "__main__":
    app.run(debug=True)
