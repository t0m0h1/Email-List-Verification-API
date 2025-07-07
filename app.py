from flask import Flask, request, jsonify
import re
import dns.resolver
import requests

app = Flask(__name__)

DISPOSABLE_DOMAINS = set([
    "mailinator.com", "10minutemail.com", "temp-mail.org"
    # Expand this list from a reliable source or file
])

EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

def check_syntax(email):
    return bool(EMAIL_REGEX.match(email))

def domain_exists(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return True if answers else False
    except Exception:
        return False

def has_mx_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return True if answers else False
    except Exception:
        return False

def is_disposable(domain):
    return domain.lower() in DISPOSABLE_DOMAINS

@app.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    email = data.get('email', '').strip()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    valid_syntax = check_syntax(email)
    domain = email.split('@')[-1] if valid_syntax else None
    domain_check = domain_exists(domain) if domain else False
    mx_check = has_mx_record(domain) if domain else False
    disposable_check = is_disposable(domain) if domain else False

    overall_status = "invalid"
    if valid_syntax and domain_check and mx_check and not disposable_check:
        overall_status = "valid"
    elif disposable_check:
        overall_status = "disposable"

    result = {
        "email": email,
        "valid_syntax": valid_syntax,
        "domain_exists": domain_check,
        "mx_records_found": mx_check,
        "disposable": disposable_check,
        "smtp_check": None,  # Optional future addition
        "overall_status": overall_status
    }
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
