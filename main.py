from sys import flags, platform
import streamlit as st
st.title("RecruitShield AI Scam Detection & Verification")
from flask import Flask, request, jsonify, render_template
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from sympy import content
from crowd_reports import check_company_reports, save_report
from fraud_predictor import predict_scam_risk
from pattern_updater import (
    detect_new_scam_pattern,
    update_patterns
)

# Import Dashboard module
from dashboard import dashboard_bp, initialize_analytics_tables, log_scam_incident, aggregate_daily_trends

update_patterns()
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


# ============================================================
# CONFIGURATION
# ============================================================

app = Flask(__name__)

# Register dashboard blueprint
app.register_blueprint(dashboard_bp)

DATABASE = "scamshield.db"
BLOCKCHAIN_FILE = "scam_blockchain.json"

# Common risky keywords
RISKY_KEYWORDS = [
    "security deposit",
    "refundable deposit",
    "registration fee",
    "processing fee",
    "training fee",
    "pay to get job",
    "send money",
    "immediate payment",
    "guaranteed job",
    "100% guaranteed job",
    "work from home and earn",
    "limited seats",
    "urgent hiring",
    "no interview",
    "whatsapp only",
    "telegram only",
    "click here immediately",
    "share otp",
    "bank details",
    "pay before joining"
]

SUSPICIOUS_PHRASES = [
    "you are selected",
    "congratulations you are hired",
    "earn lakhs",
    "easy money",
    "instant joining",
    "no experience required",
    "investment required",
    "pay first",
    "refundable amount",
]

FREE_EMAIL_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "protonmail.com",
    "icloud.com"
]


# ============================================================
# DATABASE
# ============================================================

def get_db():
    """Create database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Create required tables."""

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            source TEXT,
            category TEXT,
            confidence INTEGER,
            created_at TEXT,
            content_hash TEXT UNIQUE,
            blockchain_index INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT,
            source TEXT,
            trust_score INTEGER,
            verdict TEXT,
            flags TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()

    # Initialize analytics tables
    initialize_analytics_tables()


# ============================================================
# BLOCKCHAIN-ANCHORED SCAM REGISTRY
# ============================================================

def calculate_hash(data):
    """Generate SHA-256 hash."""

    encoded = json.dumps(
        data,
        sort_keys=True,
        default=str
    ).encode()

    return hashlib.sha256(encoded).hexdigest()


def load_blockchain():
    """Load blockchain from file."""

    if not os.path.exists(BLOCKCHAIN_FILE):

        genesis_block = {
            "index": 0,
            "timestamp": str(datetime.utcnow()),
            "previous_hash": "0",
            "data": "GENESIS BLOCK",
        }

        genesis_block["hash"] = calculate_hash(genesis_block)

        blockchain = [genesis_block]

        save_blockchain(blockchain)

        return blockchain

    try:
        with open(BLOCKCHAIN_FILE, "r") as file:
            return json.load(file)

    except Exception:
        return []


def save_blockchain(blockchain):
    """Save blockchain."""

    with open(BLOCKCHAIN_FILE, "w") as file:
        json.dump(
            blockchain,
            file,
            indent=4
        )


def add_to_blockchain(report):
    """
    Add confirmed scam report to blockchain.

    Each block contains:
    - Scam report hash
    - Timestamp
    - Previous block hash
    - Current block hash
    """

    blockchain = load_blockchain()

    previous_block = blockchain[-1]

    new_block = {
        "index": len(blockchain),
        "timestamp": str(datetime.utcnow()),
        "previous_hash": previous_block["hash"],
        "data": report
    }

    new_block["hash"] = calculate_hash(new_block)

    blockchain.append(new_block)

    save_blockchain(blockchain)

    return new_block


def verify_blockchain():
    """Verify blockchain integrity."""

    blockchain = load_blockchain()

    if len(blockchain) == 0:
        return False

    for i in range(1, len(blockchain)):

        current_block = blockchain[i]
        previous_block = blockchain[i - 1]

        stored_hash = current_block["hash"]

        block_copy = current_block.copy()
        del block_copy["hash"]

        recalculated_hash = calculate_hash(block_copy)

        if stored_hash != recalculated_hash:
            return False

        if current_block["previous_hash"] != previous_block["hash"]:
            return False

    return True


# ============================================================
# DOMAIN ANALYSIS
# ============================================================

def extract_urls(text):
    """Extract URLs from text."""

    pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'

    return re.findall(
        pattern,
        text,
        re.IGNORECASE
    )


def extract_emails(text):
    """Extract email addresses."""

    pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'

    return re.findall(pattern, text)


def get_domain_age_days(domain):
    """
    Check approximate domain age using WHOIS.

    Returns:
        age in days or None
    """

    if not WHOIS_AVAILABLE:
        return None

    try:

        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:

            age = datetime.now() - creation_date

            return age.days

    except Exception:
        return None

    return None


def analyze_domain(url):
    """Analyze suspicious domain characteristics."""

    flags = []

    domain = urlparse(
        url if url.startswith("http") else "https://" + url
    ).netloc

    domain = domain.replace("www.", "")

    if not domain:
        return flags

    age = get_domain_age_days(domain)

    if age is not None:

        if age < 30:

            flags.append({
                "risk": "HIGH",
                "reason": f"Recruiter domain '{domain}' was registered only {age} days ago.",
                "score_penalty": 25
            })

        elif age < 90:

            flags.append({
                "risk": "MEDIUM",
                "reason": f"Recruiter domain '{domain}' is relatively new ({age} days old).",
                "score_penalty": 10
            })

    return flags

# ============================================================
# COMPANY & RECRUITER IDENTITY VERIFICATION
# ============================================================

def normalize_domain(value):
    """
    Normalize a domain for comparison.
    """
    if not value:
        return None

    value = value.lower().strip()

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)

    domain = parsed.netloc.lower()

    # Remove port number
    domain = domain.split(":")[0]

    # Remove www.
    if domain.startswith("www."):
        domain = domain[4:]

    return domain or None


def extract_email_domain(email):
    """
    Extract domain from recruiter email.
    """
    if not email or "@" not in email:
        return None

    return email.split("@")[-1].lower().strip()


def is_free_email_domain(domain):
    """
    Check whether email uses a free email provider.
    """
    return (
        domain in FREE_EMAIL_DOMAINS
        if domain
        else False
    )


def domains_match(recruiter_domain, company_domain):
    """
    Check whether recruiter email belongs
    to the claimed company domain.

    Supports subdomains.
    """

    recruiter_domain = normalize_domain(recruiter_domain)
    company_domain = normalize_domain(company_domain)

    if not recruiter_domain or not company_domain:
        return False

    if recruiter_domain == company_domain:
        return True

    if recruiter_domain.endswith("." + company_domain):
        return True

    return False


def get_whois_information(domain):
    """
    Retrieve WHOIS information for a domain.
    """

    result = {
        "available": WHOIS_AVAILABLE,
        "domain": domain,
        "creation_date": None,
        "age_days": None,
        "registrar": None
    }

    if not WHOIS_AVAILABLE or not domain:
        return result

    try:

        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:

            # Handle timezone-aware datetime
            if getattr(creation_date, "tzinfo", None):
                creation_date = creation_date.replace(tzinfo=None)

            age_days = (
                datetime.now() - creation_date
            ).days

            result["creation_date"] = str(
                creation_date
            )

            result["age_days"] = age_days

        registrar = getattr(
            domain_info,
            "registrar",
            None
        )

        if registrar:
            result["registrar"] = str(registrar)

    except Exception as error:

        result["error"] = str(error)

    return result


def validate_company_page(company_website, company_name=None):
    """
    Optional validation of company website.

    Checks:
    - Page accessibility
    - Page title
    - Basic company-name presence

    This does NOT automatically trust a LinkedIn page.
    """

    result = {
        "checked": False,
        "accessible": False,
        "company_name_found": False,
        "title": None,
        "url": company_website
    }

    if not company_website:
        return result

    try:

        response = requests.get(
            company_website,
            timeout=8,
            headers={
                "User-Agent":
                "Mozilla/5.0 "
                "(RecruitShield Identity Verification)"
            }
        )

        result["checked"] = True

        if response.status_code != 200:
            result["status_code"] = response.status_code
            return result

        result["accessible"] = True

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        title = soup.title.string if soup.title else ""

        title = title.strip() if title else ""

        result["title"] = title

        if company_name and title:

            result["company_name_found"] = (
                company_name.lower()
                in title.lower()
            )

    except Exception as error:

        result["error"] = str(error)

    return result


def verify_company_recruiter_identity(
    recruiter_email=None,
    company_website=None,
    company_name=None,
    linkedin_url=None
):
    """
    Cross-check recruiter email domain against
    claimed company domain.

    Also performs:
    - WHOIS domain-age check
    - Optional company website validation
    - Optional LinkedIn URL validation
    """

    result = {
        "status": "NOT CHECKED",
        "risk": "UNKNOWN",
        "recruiter_email": recruiter_email,
        "recruiter_domain": None,
        "company_domain": None,
        "domain_match": None,
        "free_email": False,
        "whois": {},
        "company_page": {},
        "linkedin": {},
        "flags": [],
        "score_penalty": 0
    }

    # ----------------------------------------
    # 1. Extract recruiter domain
    # ----------------------------------------

    recruiter_domain = extract_email_domain(
        recruiter_email
    )

    result["recruiter_domain"] = recruiter_domain

    if not recruiter_domain:
        result["status"] = "INSUFFICIENT DATA"
        return result

    # ----------------------------------------
    # 2. Free email detection
    # ----------------------------------------

    if is_free_email_domain(recruiter_domain):

        result["free_email"] = True

        flag = {
            "risk": "MEDIUM",
            "reason":
                f"Recruiter uses a free email provider "
                f"({recruiter_domain}) instead of an "
                f"official company domain.",
            "score_penalty": 8
        }

        result["flags"].append(flag)
        result["score_penalty"] += 8

    # ----------------------------------------
    # 3. Extract company domain
    # ----------------------------------------

    company_domain = normalize_domain(
        company_website
    )

    result["company_domain"] = company_domain

    if not company_domain:
        result["status"] = "INSUFFICIENT DATA"
        return result

    # ----------------------------------------
    # 4. Compare domains
    # ----------------------------------------

    match = domains_match(
        recruiter_domain,
        company_domain
    )

    result["domain_match"] = match

    if match:

        result["status"] = "VERIFIED"
        result["risk"] = "LOW"

    else:

        result["status"] = "DOMAIN MISMATCH"
        result["risk"] = "HIGH"

        flag = {
            "risk": "HIGH",
            "reason":
                f"Recruiter email domain "
                f"'{recruiter_domain}' does not match "
                f"the claimed company domain "
                f"'{company_domain}'.",
            "score_penalty": 25
        }

        result["flags"].append(flag)
        result["score_penalty"] += 25

    # ----------------------------------------
    # 5. WHOIS domain check
    # ----------------------------------------

    whois_data = get_whois_information(
        recruiter_domain
    )

    result["whois"] = whois_data

    age = whois_data.get("age_days")

    if age is not None:

        if age < 30:

            flag = {
                "risk": "HIGH",
                "reason":
                    f"Recruiter domain '{recruiter_domain}' "
                    f"was registered only {age} days ago.",
                "score_penalty": 20
            }

            result["flags"].append(flag)
            result["score_penalty"] += 20

        elif age < 90:

            flag = {
                "risk": "MEDIUM",
                "reason":
                    f"Recruiter domain '{recruiter_domain}' "
                    f"is relatively new ({age} days old).",
                "score_penalty": 10
            }

            result["flags"].append(flag)
            result["score_penalty"] += 10

    # ----------------------------------------
    # 6. Company website validation
    # ----------------------------------------

    if company_website:

        result["company_page"] = (
            validate_company_page(
                company_website,
                company_name
            )
        )

    # ----------------------------------------
    # 7. LinkedIn URL validation
    # ----------------------------------------

    if linkedin_url:

        linkedin_domain = normalize_domain(
            linkedin_url
        )

        valid_linkedin = (
            linkedin_domain == "linkedin.com"
            or (
                linkedin_domain
                and linkedin_domain.endswith(
                    ".linkedin.com"
                )
            )
        )

        result["linkedin"] = {
            "provided": True,
            "url": linkedin_url,
            "valid_domain": valid_linkedin
        }

        if not valid_linkedin:

            flag = {
                "risk": "MEDIUM",
                "reason":
                    "The supplied LinkedIn URL does not "
                    "belong to linkedin.com.",
                "score_penalty": 10
            }

            result["flags"].append(flag)
            result["score_penalty"] += 10

    # ----------------------------------------
    # Final status
    # ----------------------------------------

    if (
        result["domain_match"] is True
        and result["score_penalty"] == 0
    ):
        result["status"] = "VERIFIED"
        result["risk"] = "LOW"

    elif result["domain_match"] is False:
        result["status"] = "DOMAIN MISMATCH"
        result["risk"] = "HIGH"

    return result


# ============================================================
# SCAM REGISTRY CHECK
# ============================================================

def check_scam_registry(content):
    """Check whether similar content was previously reported."""

    conn = get_db()
    cursor = conn.cursor()

    content_hash = hashlib.sha256(
        content.lower().strip().encode()
    ).hexdigest()

    cursor.execute("""
        SELECT * FROM scam_reports
        WHERE content_hash = ?
    """, (content_hash,))

    result = cursor.fetchone()

    conn.close()

    if result:

        return {
            "found": True,
            "report": dict(result)
        }

    return {
        "found": False
    }


# ============================================================
# REAL-TIME TRUST SCORE ENGINE
# ============================================================

def analyze_content(
    content,
    recruiter_email=None,
    company_website=None,
    company_name=None,
    linkedin_url=None,
    platform="unknown"
):
    """
    Main AI/rule-based trust analysis engine.

    Returns:
        trust_score
        verdict
        red_flags
        recommendations
    """

    content_lower = content.lower()

    score = 100
    flags = []
    recommendations = []

    # --------------------------------------------------------
    # Predictive Fraud Analytics
    # --------------------------------------------------------

    predicted_risk = predict_scam_risk(platform)

    if predicted_risk == "Very High":

        score -= 20

        flags.append({
            "risk": "HIGH",
            "reason": f"AI predicts a scam spike on {platform}.",
            "score_penalty": 20
        })

    elif predicted_risk == "High":

        score -= 15

        flags.append({
            "risk": "MEDIUM",
            "reason": f"Fraud activity is increasing on {platform}.",
            "score_penalty": 15
        })

    elif predicted_risk == "Medium":

        score -= 8

        flags.append({
            "risk": "LOW",
            "reason": f"Some fraud activity detected on {platform}.",
            "score_penalty": 8
        })

    # --------------------------------------------------------
    # Identity verification
    # --------------------------------------------------------

    identity_result = {
        "status": "NOT CHECKED",
        "risk": "UNKNOWN",
        "score_penalty": 0,
        "flags": []
    }

    if recruiter_email and company_website:
        identity_result = verify_company_recruiter_identity(
            recruiter_email=recruiter_email,
            company_website=company_website,
            company_name=company_name,
            linkedin_url=linkedin_url
        )

        score -= identity_result["score_penalty"]

        flags.extend(identity_result["flags"])

    # --------------------------------------------------------
    # Emerging Scam Pattern Detection
    # --------------------------------------------------------

    if detect_new_scam_pattern(content):

        score -= 15

        flags.append({
            "risk": "HIGH",
            "reason": "Emerging scam pattern detected from updated fraud intelligence feeds.",
            "score_penalty": 15
        })

    # --------------------------------------------------------
    # 1. Check risky keywords
    # --------------------------------------------------------

    for keyword in RISKY_KEYWORDS:

        if keyword in content_lower:

            penalty = 15

            if "deposit" in keyword or "fee" in keyword:

                penalty = 25

            score -= penalty

            flags.append({
                "risk": "HIGH",
                "reason": f"Suspicious phrase detected: '{keyword}'. Legitimate employers generally do not require payment to offer employment.",
                "score_penalty": penalty
            })

    # --------------------------------------------------------
    # 2. Check suspicious phrases
    # --------------------------------------------------------

    for phrase in SUSPICIOUS_PHRASES:

        if phrase in content_lower:

            score -= 8

            flags.append({
                "risk": "MEDIUM",
                "reason": f"Potentially suspicious recruitment language detected: '{phrase}'.",
                "score_penalty": 8
            })

    # --------------------------------------------------------
    # 3. Check excessive urgency
    # --------------------------------------------------------

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "today only",
        "limited time",
        "within 1 hour"
    ]

    urgency_count = sum(
        1 for word in urgency_words
        if word in content_lower
    )

    if urgency_count >= 2:

        score -= 10

        flags.append({
            "risk": "MEDIUM",
            "reason": "Multiple urgency tactics detected. Scammers often pressure victims to act quickly.",
            "score_penalty": 10
        })

    # --------------------------------------------------------
    # 4. Email analysis
    # --------------------------------------------------------

    emails = extract_emails(content)

    for email in emails:

        domain = email.split("@")[-1].lower()

        if domain in FREE_EMAIL_DOMAINS:

            score -= 8

            flags.append({
                "risk": "MEDIUM",
                "reason": f"Recruiter uses a free email provider ({domain}) instead of an official company domain.",
                "score_penalty": 8
            })

    # --------------------------------------------------------
    # 5. URL / Domain analysis
    # --------------------------------------------------------

    urls = extract_urls(content)

    for url in urls:

        domain_flags = analyze_domain(url)

        for flag in domain_flags:

            score -= flag["score_penalty"]

            flags.append(flag)

    # --------------------------------------------------------
    # 6. Check scam registry
    # --------------------------------------------------------

    registry_result = check_scam_registry(content)

    if registry_result["found"]:

        score -= 60

        flags.append({
            "risk": "CRITICAL",
            "reason": "This exact message/posting has already been reported in the Scam Registry.",
            "score_penalty": 60
        })

    # --------------------------------------------------------
    # Prevent score below 0
    # --------------------------------------------------------

    score = max(0, score)

    # --------------------------------------------------------
    # Determine verdict
    # --------------------------------------------------------

    if score >= 80:

        verdict = {
            "label": "LIKELY SAFE",
            "level": "LOW RISK",
            "emoji": "🟢",
            "color": "green"
        }

        recommendations.append(
            "No major red flags were detected, but independently verify the company before sharing sensitive information."
        )

    elif score >= 50:

        verdict = {
            "label": "CAUTION",
            "level": "MEDIUM RISK",
            "emoji": "🟡",
            "color": "yellow"
        }

        recommendations.append(
            "Verify the company website, recruiter identity, and job details before proceeding."
        )

        recommendations.append(
            "Do not pay money, share OTPs, passwords, or banking credentials."
        )

    else:

        verdict = {
            "label": "HIGH RISK",
            "level": "LIKELY SCAM",
            "emoji": "🔴",
            "color": "red"
        }

        recommendations.append("Do not send money or provide sensitive personal or banking information.")

        recommendations.append("Verify the company through its official website and contact channels.")

        recommendations.append("Consider reporting this message to the Scam Registry.")

    return {
        "trust_score": score,
        "verdict": verdict,
        "red_flags": flags,
        "recommendations": recommendations,
        "registry_match": registry_result["found"],
        "identity_verification": identity_result,
        "analyzed_at": str(datetime.utcnow())
    }


# ============================================================
# SAVE ANALYSIS HISTORY
# ============================================================

def save_analysis(content, source, result):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO analysis_history
        (
            content,
            source,
            trust_score,
            verdict,
            flags,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        content,
        source,
        result["trust_score"],
        result["verdict"]["label"],
        json.dumps(result["red_flags"]),
        str(datetime.utcnow())
    ))
    conn.commit()
    conn.close()


# ============================================================
# API: ANALYZE JOB / EMAIL / MESSAGE
# ============================================================

@app.route("/api/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data or "content" not in data:

        return jsonify({
            "success": False,
            "error": "Please provide 'content'."
        }), 400

    content = data["content"]

    source = data.get(
        "source",
        "manual"
    )

    platform_name = data.get("platform", "unknown")
    company_name = data.get("company_name")
    recruiter_email = data.get("recruiter_email")
    country = data.get("country")
    region = data.get("region")
    city = data.get("city")

    result = analyze_content(
        content=content,
        recruiter_email=recruiter_email,
        company_website=data.get("company_website"),
        company_name=company_name,
        linkedin_url=data.get("linkedin_url"),
        platform=platform_name
    )

    save_analysis(
        content,
        source,
        result
    )

    # Log to analytics dashboard
    risk_level = "CRITICAL" if result["trust_score"] < 20 else (
        "HIGH" if result["trust_score"] < 50 else (
            "MEDIUM" if result["trust_score"] < 80 else "LOW"
        )
    )

    log_scam_incident(
        content=content,
        platform=platform_name,
        country=country,
        region=region,
        city=city,
        company_name=company_name,
        recruiter_email=recruiter_email,
        trust_score=result["trust_score"],
        risk_level=risk_level,
        category="recruitment scam",
        reported_by=source
    )

    return jsonify({
        "success": True,
        "source": source,
        "analysis": result
    })


# ============================================================
# API: REPORT CONFIRMED SCAM
# ============================================================

@app.route("/api/report-scam", methods=["POST"])
def report_scam():

    data = request.get_json()

    if not data or "content" not in data:

        return jsonify({
            "success": False,
            "error": "Scam content is required."
        }), 400

    content = data["content"]

    source = data.get(
        "source",
        "unknown"
    )

    category = data.get(
        "category",
        "recruitment scam"
    )

    confidence = data.get(
        "confidence",
        100
    )

    content_hash = hashlib.sha256(
        content.lower().strip().encode()
    ).hexdigest()

    # Check duplicates

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, blockchain_index
        FROM scam_reports
        WHERE content_hash = ?
    """, (content_hash,))

    existing = cursor.fetchone()

    if existing:

        conn.close()

        return jsonify({
            "success": False,
            "message": "This scam report already exists.",
            "report_id": existing["id"],
            "blockchain_index": existing["blockchain_index"]
        }), 409

    # Blockchain report data

    report_data = {
        "content_hash": content_hash,
        "source": source,
        "category": category,
        "confidence": confidence,
        "reported_at": str(datetime.utcnow())
    }

    block = add_to_blockchain(report_data)

    # Save in database

    cursor.execute("""
        INSERT INTO scam_reports
        (
            content,
            source,
            category,
            confidence,
            created_at,
            content_hash,
            blockchain_index
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        content,
        source,
        category,
        confidence,
        str(datetime.utcnow()),
        content_hash,
        block["index"]
    ))

    report_id = cursor.lastrowid

    conn.commit()

    conn.close()

    # Log to analytics
    log_scam_incident(
        content=content,
        platform=data.get("platform", "unknown"),
        country=data.get("country"),
        region=data.get("region"),
        city=data.get("city"),
        company_name=data.get("company_name"),
        recruiter_email=data.get("recruiter_email"),
        trust_score=0,
        risk_level="CRITICAL",
        category=category,
        reported_by=source
    )

    return jsonify({
        "success": True,
        "message": "Scam report successfully added to the immutable registry.",
        "report_id": report_id,
        "blockchain_block": block
    })


@app.route("/api/community-report", methods=["POST"])
def community_report():

    data = request.get_json()

    company_name = data.get("company_name")
    reason = data.get("reason")

    if not company_name or not reason:
        return jsonify({
            "success": False,
            "error": "company_name and reason are required"
        }), 400

    save_report(company_name, reason)

    return jsonify({
        "success": True,
        "message": "Community report added"
    })


# ============================================================
# API: VERIFY BLOCKCHAIN
# ============================================================

@app.route("/api/blockchain/verify", methods=["GET"])
def verify_chain():

    valid = verify_blockchain()

    blockchain = load_blockchain()

    return jsonify({
        "success": True,
        "blockchain_valid": valid,
        "total_blocks": len(blockchain)
    })


# ============================================================
# API: VIEW BLOCKCHAIN
# ============================================================

@app.route("/api/blockchain", methods=["GET"])
def get_blockchain():

    blockchain = load_blockchain()

    return jsonify({
        "success": True,
        "total_blocks": len(blockchain),
        "blocks": blockchain
    })


# ============================================================
# BROWSER EXTENSION API
# ============================================================

@app.route("/api/extension/analyze", methods=["POST"])
def extension_analyze():
    """
    Endpoint for Chrome/Edge browser extension.

    Example request:

    {
        "content": "Job posting text...",
        "platform": "linkedin",
        "url": "https://linkedin.com/jobs/..."
    }
    """

    data = request.get_json()

    if not data or "content" not in data:

        return jsonify({
            "success": False,
            "error": "Job posting content is required."
        }), 400

    content = data["content"]

    platform_name = data.get(
        "platform",
        "unknown"
    )

    result = analyze_content(
        content,
        platform=platform_name
    )

    return jsonify({
        "success": True,
        "platform": platform_name,
        "trust_score": result["trust_score"],
        "verdict": result["verdict"],
        "red_flags": result["red_flags"],
        "recommendations": result["recommendations"]
    })


# ============================================================
# COMPANY & RECRUITER IDENTITY API
# ============================================================

@app.route("/api/verify-identity", methods=["POST"])
def verify_identity():

    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "error": "JSON request body is required."
        }), 400

    recruiter_email = data.get(
        "recruiter_email"
    )

    company_website = data.get(
        "company_website"
    )

    company_name = data.get(
        "company_name"
    )

    linkedin_url = data.get(
        "linkedin_url"
    )

    if not recruiter_email:

        return jsonify({
            "success": False,
            "error": "recruiter_email is required."
        }), 400

    result = verify_company_recruiter_identity(
        recruiter_email=recruiter_email,
        company_website=company_website,
        company_name=company_name,
        linkedin_url=linkedin_url
    )

    return jsonify({
        "success": True,
        "identity_verification": result
    })


# ============================================================
# TELEGRAM BOT WEBHOOK
# ============================================================

@app.route("/webhook/telegram", methods=["POST"])
def telegram_webhook():
    """
    Receives Telegram bot messages.

    User forwards suspicious recruitment messages
    to the Telegram bot.
    """

    update = request.get_json()

    try:

        message = update.get("message", {})

        chat_id = message.get(
            "chat",
            {}
        ).get("id")

        text = message.get(
            "text",
            ""
        )

        if not text:

            return jsonify({
                "success": False,
                "message": "No text received."
            })

        result = analyze_content(text, platform="telegram")

        reply = format_bot_response(result)

        print("\n===== TELEGRAM ANALYSIS =====")

        print(f"Chat ID: {chat_id}")

        print(reply)

        return jsonify({
            "success": True,
            "chat_id": chat_id,
            "reply": reply,
            "analysis": result
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# WHATSAPP WEBHOOK
# ============================================================

@app.route("/webhook/whatsapp", methods=["POST"])
def whatsapp_webhook():
    """
    WhatsApp webhook endpoint.

    Compatible as a backend starting point for
    Twilio WhatsApp integration or Meta WhatsApp Cloud API.
    """

    try:

        incoming_message = (
            request.form.get("Body")
            or request.json.get("message", "")
        )

        sender = (
            request.form.get("From")
            or request.json.get("sender", "unknown")
        )

        if not incoming_message:

            return jsonify({
                "success": False,
                "message": "No message received."
            })

        result = analyze_content(
            incoming_message,
            platform="whatsapp"
        )

        reply = format_bot_response(result)

        print("\n===== WHATSAPP ANALYSIS =====")

        print(f"Sender: {sender}")

        print(reply)

        return jsonify({
            "success": True,
            "sender": sender,
            "reply": reply,
            "analysis": result
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# BOT RESPONSE FORMATTER
# ============================================================

def format_bot_response(result):

    verdict = result["verdict"]

    response = f"""
🔎 RECRUITMENT TRUST CHECK

Trust Score: {result['trust_score']}/100

{verdict['emoji']} Verdict:
{verdict['label']}

Risk Level:
{verdict['level']}

"""

    if result["red_flags"]:

        response += "\n🚩 RED FLAGS:\n"

        for flag in result["red_flags"]:

            response += (
                f"\n• [{flag['risk']}] "
                f"{flag['reason']}"
            )

    response += "\n\n💡 RECOMMENDATIONS:\n"

    for recommendation in result["recommendations"]:

        response += f"\n• {recommendation}"

    return response


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "system": "Recruitment Scam Detection System",
        "status": "running",
        "features": [
            "Real-Time Trust Score",
            "Explainable Red Flags",
            "Blockchain Scam Registry",
            "Browser Extension API",
            "WhatsApp Integration",
            "Telegram Integration",
            "Web Dashboard Analytics"
        ]
    })


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    initialize_database()

    load_blockchain()

    # Aggregate trends daily
    aggregate_daily_trends()

    print("=" * 60)

    print("RECRUITMENT SCAM DETECTION SYSTEM")

    print("=" * 60)

    print("Server running at:")

    print("http://127.0.0.1:5000")

    print("\nMain API:")

    print("POST /api/analyze")

    print("\nBrowser Extension API:")

    print("POST /api/extension/analyze")

    print("\nReport Scam:")

    print("POST /api/report-scam")

    print("\nBlockchain:")

    print("GET /api/blockchain")

    print("GET /api/blockchain/verify")

    print("\nBot Webhooks:")

    print("POST /webhook/telegram")

    print("POST /webhook/whatsapp")

    print("\nDashboard Analytics:")

    print("GET /dashboard/api/summary")

    print("GET /dashboard/api/heatmap/geographic")

    print("GET /dashboard/api/heatmap/platform")

    print("GET /dashboard/api/recruiter-trust-scores")

    print("GET /dashboard/api/fraud-trends")

    print("GET /dashboard/")

    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
