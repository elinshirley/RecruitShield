import streamlit as st
import sqlite3
import hashlib
import json
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from statistics import mean

# Import all helper modules
from crowd_reports import check_company_reports, save_report
from fraud_predictor import predict_scam_risk
from pattern_updater import detect_new_scam_pattern, update_patterns

# Import dashboard functions
try:
    from dashboard import initialize_analytics_tables, log_scam_incident, aggregate_daily_trends
except ImportError:
    # If dashboard module not available, create dummy functions
    def initialize_analytics_tables():
        pass
    def log_scam_incident(*args, **kwargs):
        pass
    def aggregate_daily_trends():
        pass

update_patterns()

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="🛡️ RecruitShield - Scam Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CONFIGURATION
# ============================================================

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
    """Add confirmed scam report to blockchain."""
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
    return re.findall(pattern, text, re.IGNORECASE)


def extract_emails(text):
    """Extract email addresses."""
    pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    return re.findall(pattern, text)


def get_domain_age_days(domain):
    """Check approximate domain age using WHOIS."""
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
    """Normalize a domain for comparison."""
    if not value:
        return None

    value = value.lower().strip()

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)
    domain = parsed.netloc.lower()
    domain = domain.split(":")[0]

    if domain.startswith("www."):
        domain = domain[4:]

    return domain or None


def extract_email_domain(email):
    """Extract domain from recruiter email."""
    if not email or "@" not in email:
        return None

    return email.split("@")[-1].lower().strip()


def is_free_email_domain(domain):
    """Check whether email uses a free email provider."""
    return (
        domain in FREE_EMAIL_DOMAINS
        if domain
        else False
    )


def domains_match(recruiter_domain, company_domain):
    """Check whether recruiter email belongs to the claimed company domain."""
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
    """Retrieve WHOIS information for a domain."""
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
            if getattr(creation_date, "tzinfo", None):
                creation_date = creation_date.replace(tzinfo=None)

            age_days = (
                datetime.now() - creation_date
            ).days

            result["creation_date"] = str(creation_date)
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
    """Optional validation of company website."""
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
                "User-Agent": "Mozilla/5.0 (RecruitShield Identity Verification)"
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
    """Cross-check recruiter email domain against claimed company domain."""
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

    recruiter_domain = extract_email_domain(recruiter_email)
    result["recruiter_domain"] = recruiter_domain

    if not recruiter_domain:
        result["status"] = "INSUFFICIENT DATA"
        return result

    if is_free_email_domain(recruiter_domain):
        result["free_email"] = True
        flag = {
            "risk": "MEDIUM",
            "reason": f"Recruiter uses a free email provider ({recruiter_domain}) instead of an official company domain.",
            "score_penalty": 8
        }
        result["flags"].append(flag)
        result["score_penalty"] += 8

    company_domain = normalize_domain(company_website)
    result["company_domain"] = company_domain

    if not company_domain:
        result["status"] = "INSUFFICIENT DATA"
        return result

    match = domains_match(recruiter_domain, company_domain)
    result["domain_match"] = match

    if match:
        result["status"] = "VERIFIED"
        result["risk"] = "LOW"
    else:
        result["status"] = "DOMAIN MISMATCH"
        result["risk"] = "HIGH"
        flag = {
            "risk": "HIGH",
            "reason": f"Recruiter email domain '{recruiter_domain}' does not match the claimed company domain '{company_domain}'.",
            "score_penalty": 25
        }
        result["flags"].append(flag)
        result["score_penalty"] += 25

    whois_data = get_whois_information(recruiter_domain)
    result["whois"] = whois_data
    age = whois_data.get("age_days")

    if age is not None:
        if age < 30:
            flag = {
                "risk": "HIGH",
                "reason": f"Recruiter domain '{recruiter_domain}' was registered only {age} days ago.",
                "score_penalty": 20
            }
            result["flags"].append(flag)
            result["score_penalty"] += 20
        elif age < 90:
            flag = {
                "risk": "MEDIUM",
                "reason": f"Recruiter domain '{recruiter_domain}' is relatively new ({age} days old).",
                "score_penalty": 10
            }
            result["flags"].append(flag)
            result["score_penalty"] += 10

    if company_website:
        result["company_page"] = (
            validate_company_page(
                company_website,
                company_name
            )
        )

    if linkedin_url:
        linkedin_domain = normalize_domain(linkedin_url)
        valid_linkedin = (
            linkedin_domain == "linkedin.com"
            or (
                linkedin_domain
                and linkedin_domain.endswith(".linkedin.com")
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
                "reason": "The supplied LinkedIn URL does not belong to linkedin.com.",
                "score_penalty": 10
            }
            result["flags"].append(flag)
            result["score_penalty"] += 10

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
    """Main AI/rule-based trust analysis engine."""
    content_lower = content.lower()
    score = 100
    flags = []
    recommendations = []

    # Predictive Fraud Analytics
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

    # Identity verification
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

    # Emerging Scam Pattern Detection
    if detect_new_scam_pattern(content):
        score -= 15
        flags.append({
            "risk": "HIGH",
            "reason": "Emerging scam pattern detected from updated fraud intelligence feeds.",
            "score_penalty": 15
        })

    # Check risky keywords
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

    # Check suspicious phrases
    for phrase in SUSPICIOUS_PHRASES:
        if phrase in content_lower:
            score -= 8
            flags.append({
                "risk": "MEDIUM",
                "reason": f"Potentially suspicious recruitment language detected: '{phrase}'.",
                "score_penalty": 8
            })

    # Check excessive urgency
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

    # Email analysis
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

    # URL / Domain analysis
    urls = extract_urls(content)

    for url in urls:
        domain_flags = analyze_domain(url)

        for flag in domain_flags:
            score -= flag["score_penalty"]
            flags.append(flag)

    # Check scam registry
    registry_result = check_scam_registry(content)

    if registry_result["found"]:
        score -= 60
        flags.append({
            "risk": "CRITICAL",
            "reason": "This exact message/posting has already been reported in the Scam Registry.",
            "score_penalty": 60
        })

    score = max(0, score)

    # Determine verdict
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
# STREAMLIT UI
# ============================================================

st.title("🛡️ RecruitShield AI Scam Detection & Verification")

# Initialize
initialize_database()
load_blockchain()
aggregate_daily_trends()

# Sidebar
with st.sidebar:
    st.write("**System Status:** ✅ Running")
    st.write("**Features:**")
    st.write("- Real-Time Trust Score")
    st.write("- Explainable Red Flags")
    st.write("- Blockchain Scam Registry")
    st.write("- Identity Verification")
    st.write("- Analytics Dashboard")
    st.divider()
    
    page = st.radio(
        "Select Page",
        ["🔍 Analyze Job", "📊 Dashboard", "🔗 Blockchain", "📋 Reports"]
    )

# ============================================================
# PAGE: ANALYZE JOB
# ============================================================

if page == "🔍 Analyze Job":
    st.header("Job Posting Trust Analysis")
    st.write("Paste a job posting or recruiter message to get an instant trust score")
    st.divider()
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        job_content = st.text_area(
            "📝 Enter job posting or message:",
            height=300,
            placeholder="Paste the job posting text here..."
        )
    
    with col2:
        st.subheader("📋 Details")
        platform = st.selectbox("Platform", ["linkedin", "whatsapp", "telegram", "email", "indeed", "unknown"])
        company_name = st.text_input("Company Name")
        recruiter_email = st.text_input("Recruiter Email")
        country = st.text_input("Country")
        company_website = st.text_input("Company Website")
    
    if st.button("🔍 Analyze Now", use_container_width=True, type="primary"):
        if job_content:
            with st.spinner("⏳ Analyzing... Please wait"):
                result = analyze_content(
                    content=job_content,
                    recruiter_email=recruiter_email if recruiter_email else None,
                    company_website=company_website if company_website else None,
                    company_name=company_name if company_name else None,
                    platform=platform
                )
                
                save_analysis(job_content, "streamlit", result)
                
                # Log to analytics
                risk_level = "CRITICAL" if result["trust_score"] < 20 else (
                    "HIGH" if result["trust_score"] < 50 else (
                        "MEDIUM" if result["trust_score"] < 80 else "LOW"
                    )
                )
                
                log_scam_incident(
                    content=job_content,
                    platform=platform,
                    country=country if country else None,
                    company_name=company_name if company_name else None,
                    recruiter_email=recruiter_email if recruiter_email else None,
                    trust_score=result["trust_score"],
                    risk_level=risk_level,
                    category="recruitment scam",
                    reported_by="streamlit"
                )
            
            st.success("✅ Analysis Complete")
            
            # Display results
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Trust Score", f"{result['trust_score']}/100")
            
            with col2:
                verdict = result['verdict']
                st.metric("Verdict", f"{verdict['emoji']} {verdict['label']}")
            
            with col3:
                st.metric("Risk Level", verdict['level'])
            
            st.divider()
            
            # Red Flags
            if result["red_flags"]:
                st.subheader("🚩 Red Flags Detected:")
                for flag in result["red_flags"]:
                    if flag['risk'] == 'CRITICAL':
                        st.error(f"**[{flag['risk']}]** {flag['reason']}")
                    elif flag['risk'] == 'HIGH':
                        st.warning(f"**[{flag['risk']}]** {flag['reason']}")
                    else:
                        st.info(f"**[{flag['risk']}]** {flag['reason']}")
            else:
                st.success("✅ No major red flags detected")
            
            st.divider()
            
            # Recommendations
            st.subheader("💡 Recommendations:")
            for rec in result["recommendations"]:
                st.info(f"• {rec}")
        else:
            st.error("❌ Please enter job content to analyze")

# ============================================================
# PAGE: DASHBOARD
# ============================================================

elif page == "📊 Dashboard":
    st.header("📊 Analytics Dashboard")
    
    # Get stats from database
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT COUNT(*) as total,
               AVG(trust_score) as avg_score,
               SUM(CASE WHEN risk_level IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) as critical
        FROM scam_incidents
    """)
    
    stats = cursor.fetchone()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("📊 Total Incidents", stats["total"] or 0)
    
    with col2:
        avg_score = round(stats["avg_score"] or 50)
        st.metric("⭐ Avg Trust Score", f"{avg_score}/100")
    
    with col3:
        st.metric("🚨 Critical Cases", stats["critical"] or 0)
    
    with col4:
        cursor.execute("SELECT COUNT(*) as flagged FROM recruiter_profiles WHERE status = 'FLAGGED'")
        flagged = cursor.fetchone()["flagged"]
        st.metric("👥 Flagged Recruiters", flagged or 0)
    
    st.divider()
    
    # Platform distribution
    cursor.execute("""
        SELECT platform, COUNT(*) as count
        FROM scam_incidents
        GROUP BY platform
        ORDER BY count DESC
    """)
    
    platforms = cursor.fetchall()
    if platforms:
        st.subheader("📱 Platform Distribution")
        import pandas as pd
        import plotly.express as px
        
        df = pd.DataFrame(platforms)
        fig = px.bar(df, x='platform', y='count', color='platform')
        st.plotly_chart(fig, use_container_width=True)
    
    conn.close()

# ============================================================
# PAGE: BLOCKCHAIN
# ============================================================

elif page == "🔗 Blockchain":
    st.header("🔗 Blockchain Scam Registry")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("✅ Verify Blockchain Integrity", use_container_width=True):
            valid = verify_blockchain()
            blockchain = load_blockchain()
            
            if valid:
                st.success(f"✅ Blockchain is valid and intact! Total blocks: {len(blockchain)}")
            else:
                st.error("❌ Blockchain integrity check failed!")
    
    with col2:
        if st.button("📋 View Blockchain", use_container_width=True):
            blockchain = load_blockchain()
            st.json(blockchain[-5:] if len(blockchain) > 5 else blockchain)
    
    st.divider()
    
    # Report new scam
    st.subheader("📝 Report Confirmed Scam")
    
    with st.form("scam_report_form"):
        content = st.text_area("Scam Content *", height=150)
        source = st.selectbox("Source", ["telegram", "whatsapp", "email", "linkedin", "manual"])
        category = st.text_input("Category", value="recruitment scam")
        confidence = st.slider("Confidence", 0, 100, 100)
        
        if st.form_submit_button("📤 Report to Blockchain", use_container_width=True):
            if content:
                # Check duplicates
                content_hash = hashlib.sha256(content.lower().strip().encode()).hexdigest()
                
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM scam_reports WHERE content_hash = ?", (content_hash,))
                existing = cursor.fetchone()
                
                if existing:
                    st.warning("⚠️ This report already exists in the database")
                else:
                    # Add to blockchain
                    report_data = {
                        "content_hash": content_hash,
                        "source": source,
                        "category": category,
                        "confidence": confidence,
                        "reported_at": str(datetime.utcnow())
                    }
                    
                    block = add_to_blockchain(report_data)
                    
                    # Save to database
                    cursor.execute("""
                        INSERT INTO scam_reports
                        (content, source, category, confidence, created_at, content_hash, blockchain_index)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        content, source, category, confidence,
                        str(datetime.utcnow()), content_hash, block["index"]
                    ))
                    
                    conn.commit()
                    st.success(f"✅ Scam report added to blockchain! Block #{block['index']}")
                
                conn.close()
            else:
                st.error("❌ Please enter scam content")

# ============================================================
# PAGE: REPORTS
# ============================================================

elif page == "📋 Reports":
    st.header("📋 Analysis History & Reports")
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get recent analyses
    cursor.execute("""
        SELECT * FROM analysis_history
        ORDER BY created_at DESC
        LIMIT 20
    """)
    
    analyses = cursor.fetchall()
    
    if analyses:
        st.subheader("Recent Analyses")
        
        for analysis in analyses:
            with st.expander(f"📌 {analysis['verdict']} - Score: {analysis['trust_score']}/100"):
                st.write(f"**Source:** {analysis['source']}")
                st.write(f"**Time:** {analysis['created_at']}")
                st.write(f"**Content Preview:** {analysis['content'][:200]}...")
                st.write(f"**Flags:** {json.loads(analysis['flags'])}")
    else:
        st.info("No analyses yet")
    
    conn.close()

# ============================================================
# FOOTER
# ============================================================

st.divider()
st.markdown("""
    <div style="text-align: center; color: #666; font-size: 12px;">
        <p>🛡️ <strong>RecruitShield</strong> - Protecting Job Seekers from Recruitment Fraud</p>
        <p>© 2026 | Blockchain-Anchored Scam Registry | AI-Powered Detection</p>
    </div>
""", unsafe_allow_html=True)
