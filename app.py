from flask import Flask, request, jsonify, abort
from functools import wraps
import re
import dns.resolver
import smtplib
from email_validator import validate_email, EmailNotValidError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- Flask Setup ---
app = Flask(__name__)
limiter = Limiter(app=app, key_func=get_remote_address)


# --- Config ---
VALID_API_KEYS = {"demo-key-123"}
DISPOSABLE_DOMAINS_FILE = "disposable_domains.txt"

# --- Load disposable domains once ---
def load_disposable_domains():
    try:
        with open(DISPOSABLE_DOMAINS_FILE) as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()

DISPOSABLE_DOMAINS = load_disposable_domains()

# --- Middleware for API Key ---
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("x-api-key")
        if key not in VALID_API_KEYS:
            abort(403, description="Invalid or missing API key")
        return f(*args, **kwargs)
    return decorated

# --- Email Validation ---
def check_syntax(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def domain_exists(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except Exception:
        return False

def has_mx_record(domain):
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except Exception:
        return False

def is_disposable(domain):
    return domain.lower() in DISPOSABLE_DOMAINS

def smtp_check(email, domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)

        server = smtplib.SMTP(timeout=10)
        server.connect(mx_record)
        server.helo("yourdomain.com")
        server.mail("verify@yourdomain.com")
        code, message = server.rcpt(email)
        server.quit()

        return code == 250
    except Exception:
        return None

# --- Main API Route ---
@app.route("/verify-email", methods=["POST"])
@require_api_key
@limiter.limit("100/day")
def verify_email():
    data = request.get_json()
    email = data.get("email", "").strip()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    valid_syntax = check_syntax(email)
    domain = email.split('@')[-1].lower() if valid_syntax else None

    domain_check = domain_exists(domain) if domain else False
    mx_check = has_mx_record(domain) if domain else False
    disposable_check = is_disposable(domain) if domain else False
    smtp_result = smtp_check(email, domain) if domain_check and mx_check else None

    if valid_syntax and domain_check and mx_check and smtp_result and not disposable_check:
        overall_status = "valid"
    elif disposable_check:
        overall_status = "disposable"
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

# --- Optional: Home route ---
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Email Verification API is running."})

# --- Entry Point ---
if __name__ == "__main__":
    app.run(debug=True)
