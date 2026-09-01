"""
Web Dashboard Analytics Module

Provides a centralized hub for:
- Scam heatmaps (geographic and platform-based)
- Recruiter trust scores
- Fraud trend reports
- Real-time analytics
- Judge appeal documentation
"""

from flask import Blueprint, render_template, jsonify, request
import sqlite3
from datetime import datetime, timedelta
import json
from collections import defaultdict
from statistics import mean, median
import os

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

DATABASE = "scamshield.db"


def get_db():
    """Create database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# DATABASE SCHEMA FOR ANALYTICS
# ============================================================

def initialize_analytics_tables():
    """Create analytics-specific tables."""
    conn = get_db()
    cursor = conn.cursor()

    # Geographic and platform heatmap data
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scam_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            platform TEXT,
            country TEXT,
            region TEXT,
            city TEXT,
            company_name TEXT,
            recruiter_email TEXT,
            trust_score INTEGER,
            risk_level TEXT,
            category TEXT,
            created_at TEXT,
            reported_by TEXT
        )
    """)

    # Recruiter tracking for trust scoring
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS recruiter_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            company_name TEXT,
            domain TEXT,
            total_reports INTEGER DEFAULT 0,
            flagged_count INTEGER DEFAULT 0,
            verified_count INTEGER DEFAULT 0,
            trust_score INTEGER,
            status TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    """)

    # Fraud trends tracking
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fraud_trends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            platform TEXT,
            scam_count INTEGER,
            average_trust_score INTEGER,
            high_risk_count INTEGER,
            medium_risk_count INTEGER,
            low_risk_count INTEGER
        )
    """)

    # Appeal case documentation
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS appeal_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            victim_email TEXT,
            incident_id INTEGER,
            appeal_reason TEXT,
            evidence TEXT,
            status TEXT,
            judge_notes TEXT,
            created_at TEXT,
            resolved_at TEXT,
            resolution TEXT,
            FOREIGN KEY(incident_id) REFERENCES scam_incidents(id)
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# DATA COLLECTION & AGGREGATION
# ============================================================

def log_scam_incident(
    content,
    platform="unknown",
    country=None,
    region=None,
    city=None,
    company_name=None,
    recruiter_email=None,
    trust_score=50,
    risk_level="MEDIUM",
    category="recruitment scam",
    reported_by=None
):
    """
    Log a scam incident for analytics.
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scam_incidents
        (
            content,
            platform,
            country,
            region,
            city,
            company_name,
            recruiter_email,
            trust_score,
            risk_level,
            category,
            created_at,
            reported_by
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        content,
        platform,
        country,
        region,
        city,
        company_name,
        recruiter_email,
        trust_score,
        risk_level,
        category,
        str(datetime.utcnow()),
        reported_by
    ))

    incident_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Update recruiter profile
    if recruiter_email:
        update_recruiter_profile(
            recruiter_email,
            company_name,
            trust_score,
            risk_level
        )

    return incident_id


def update_recruiter_profile(email, company_name=None, trust_score=None, risk_level=None):
    """
    Update or create recruiter profile with cumulative trust scoring.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Check if recruiter exists
    cursor.execute(
        "SELECT * FROM recruiter_profiles WHERE email = ?",
        (email,)
    )

    existing = cursor.fetchone()

    if existing:
        # Update existing profile
        total_reports = existing["total_reports"] + 1
        flagged_count = existing["flagged_count"]

        if risk_level == "HIGH" or risk_level == "CRITICAL":
            flagged_count += 1

        # Recalculate trust score
        new_trust_score = max(0, 100 - (flagged_count * 15))

        cursor.execute("""
            UPDATE recruiter_profiles
            SET total_reports = ?,
                flagged_count = ?,
                trust_score = ?,
                last_seen = ?
            WHERE email = ?
        """, (
            total_reports,
            flagged_count,
            new_trust_score,
            str(datetime.utcnow()),
            email
        ))

    else:
        # Create new profile
        flagged_count = 1 if (risk_level == "HIGH" or risk_level == "CRITICAL") else 0
        new_trust_score = max(0, 100 - (flagged_count * 15))

        domain = email.split("@")[-1] if "@" in email else "unknown"

        cursor.execute("""
            INSERT INTO recruiter_profiles
            (
                email,
                company_name,
                domain,
                total_reports,
                flagged_count,
                trust_score,
                status,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            email,
            company_name,
            domain,
            1,
            flagged_count,
            new_trust_score,
            "FLAGGED" if flagged_count > 0 else "VERIFIED",
            str(datetime.utcnow()),
            str(datetime.utcnow())
        ))

    conn.commit()
    conn.close()


def aggregate_daily_trends():
    """
    Aggregate fraud trends for each day.
    Called periodically (hourly/daily) to create trend data.
    """
    conn = get_db()
    cursor = conn.cursor()

    today = datetime.utcnow().date()

    # Check if already aggregated today
    cursor.execute(
        "SELECT id FROM fraud_trends WHERE date = ?",
        (str(today),)
    )

    if cursor.fetchone():
        conn.close()
        return

    # Get all incidents from today
    cursor.execute("""
        SELECT platform, trust_score, risk_level
        FROM scam_incidents
        WHERE DATE(created_at) = ?
    """, (str(today),))

    incidents = cursor.fetchall()

    if not incidents:
        conn.close()
        return

    # Aggregate by platform
    platform_data = defaultdict(lambda: {
        "scam_count": 0,
        "scores": [],
        "high": 0,
        "medium": 0,
        "low": 0
    })

    for incident in incidents:
        platform = incident["platform"] or "unknown"
        platform_data[platform]["scam_count"] += 1
        platform_data[platform]["scores"].append(incident["trust_score"])

        if incident["risk_level"] == "HIGH" or incident["risk_level"] == "CRITICAL":
            platform_data[platform]["high"] += 1
        elif incident["risk_level"] == "MEDIUM":
            platform_data[platform]["medium"] += 1
        else:
            platform_data[platform]["low"] += 1

    # Insert aggregated data
    for platform, data in platform_data.items():
        avg_score = int(mean(data["scores"])) if data["scores"] else 50

        cursor.execute("""
            INSERT INTO fraud_trends
            (date, platform, scam_count, average_trust_score, high_risk_count, medium_risk_count, low_risk_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            str(today),
            platform,
            data["scam_count"],
            avg_score,
            data["high"],
            data["medium"],
            data["low"]
        ))

    conn.commit()
    conn.close()


# ============================================================
# ANALYTICS API ENDPOINTS
# ============================================================

@dashboard_bp.route("/api/heatmap/geographic", methods=["GET"])
def get_geographic_heatmap():
    """
    Get geographic heatmap data for scam distribution.
    Returns scam incidents by country/region.
    """
    conn = get_db()
    cursor = conn.cursor()

    days = request.args.get("days", 30, type=int)
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    cursor.execute("""
        SELECT country, region, city, COUNT(*) as incident_count,
               AVG(trust_score) as avg_trust_score
        FROM scam_incidents
        WHERE country IS NOT NULL AND created_at > ?
        GROUP BY country, region, city
        ORDER BY incident_count DESC
    """, (start_date,))

    results = cursor.fetchall()
    conn.close()

    heatmap_data = [
        {
            "country": row["country"],
            "region": row["region"],
            "city": row["city"],
            "incident_count": row["incident_count"],
            "avg_trust_score": row["avg_trust_score"],
            "severity": "HIGH" if row["incident_count"] > 50 else (
                "MEDIUM" if row["incident_count"] > 10 else "LOW"
            )
        }
        for row in results
    ]

    return jsonify({
        "success": True,
        "heatmap_data": heatmap_data,
        "time_range_days": days,
        "generated_at": str(datetime.utcnow())
    })


@dashboard_bp.route("/api/heatmap/platform", methods=["GET"])
def get_platform_heatmap():
    """
    Get platform-based scam distribution heatmap.
    Shows scam incidents by platform (LinkedIn, WhatsApp, Telegram, etc.)
    """
    conn = get_db()
    cursor = conn.cursor()

    days = request.args.get("days", 30, type=int)
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    cursor.execute("""
        SELECT platform, COUNT(*) as incident_count,
               AVG(trust_score) as avg_trust_score,
               SUM(CASE WHEN risk_level IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) as critical_count
        FROM scam_incidents
        WHERE created_at > ?
        GROUP BY platform
        ORDER BY incident_count DESC
    """, (start_date,))

    results = cursor.fetchall()
    conn.close()

    platform_data = [
        {
            "platform": row["platform"] or "unknown",
            "incident_count": row["incident_count"],
            "avg_trust_score": row["avg_trust_score"],
            "critical_incidents": row["critical_count"],
            "risk_percentage": round(
                (row["critical_count"] / row["incident_count"] * 100) if row["incident_count"] > 0 else 0,
                2
            )
        }
        for row in results
    ]

    return jsonify({
        "success": True,
        "platform_data": platform_data,
        "time_range_days": days,
        "generated_at": str(datetime.utcnow())
    })


@dashboard_bp.route("/api/recruiter-trust-scores", methods=["GET"])
def get_recruiter_trust_scores():
    """
    Get recruiter trust score rankings.
    Shows most flagged and verified recruiters.
    """
    conn = get_db()
    cursor = conn.cursor()

    limit = request.args.get("limit", 50, type=int)
    sort_by = request.args.get("sort_by", "trust_score", type=str)

    if sort_by == "total_reports":
        order = "total_reports DESC"
    else:
        order = "trust_score ASC"

    cursor.execute(f"""
        SELECT email, company_name, domain, total_reports, flagged_count,
               verified_count, trust_score, status, first_seen, last_seen
        FROM recruiter_profiles
        ORDER BY {order}
        LIMIT ?
    """, (limit,))

    results = cursor.fetchall()
    conn.close()

    recruiter_data = [
        {
            "email": row["email"],
            "company_name": row["company_name"],
            "domain": row["domain"],
            "total_reports": row["total_reports"],
            "flagged_count": row["flagged_count"],
            "verified_count": row["verified_count"],
            "trust_score": row["trust_score"],
            "status": row["status"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "risk_level": "CRITICAL" if row["trust_score"] < 30 else (
                "HIGH" if row["trust_score"] < 60 else (
                    "MEDIUM" if row["trust_score"] < 80 else "LOW"
                )
            )
        }
        for row in results
    ]

    return jsonify({
        "success": True,
        "recruiters": recruiter_data,
        "total_count": len(recruiter_data),
        "sort_by": sort_by,
        "generated_at": str(datetime.utcnow())
    })


@dashboard_bp.route("/api/fraud-trends", methods=["GET"])
def get_fraud_trends():
    """
    Get fraud trend analysis over time.
    Shows trends by platform and overall statistics.
    """
    conn = get_db()
    cursor = conn.cursor()

    days = request.args.get("days", 30, type=int)
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    # Get trends data
    cursor.execute("""
        SELECT date, platform, scam_count, average_trust_score,
               high_risk_count, medium_risk_count, low_risk_count
        FROM fraud_trends
        WHERE date >= ?
        ORDER BY date DESC
    """, (str(start_date.split('T')[0]),))

    trends = cursor.fetchall()

    # Get overall statistics
    cursor.execute("""
        SELECT COUNT(*) as total_incidents,
               AVG(trust_score) as avg_trust_score,
               SUM(CASE WHEN risk_level IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) as critical_count,
               SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
               SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_count
        FROM scam_incidents
        WHERE created_at > ?
    """, (start_date,))

    overall_stats = cursor.fetchone()
    conn.close()

    trends_data = [
        {
            "date": row["date"],
            "platform": row["platform"],
            "scam_count": row["scam_count"],
            "average_trust_score": row["average_trust_score"],
            "high_risk_count": row["high_risk_count"],
            "medium_risk_count": row["medium_risk_count"],
            "low_risk_count": row["low_risk_count"]
        }
        for row in trends
    ]

    return jsonify({
        "success": True,
        "trends": trends_data,
        "overall_statistics": {
            "total_incidents": overall_stats["total_incidents"],
            "average_trust_score": overall_stats["avg_trust_score"],
            "critical_incidents": overall_stats["critical_count"],
            "medium_incidents": overall_stats["medium_count"],
            "low_incidents": overall_stats["low_count"]
        },
        "time_range_days": days,
        "generated_at": str(datetime.utcnow())
    })


@dashboard_bp.route("/api/fraud-categories", methods=["GET"])
def get_fraud_categories():
    """
    Get breakdown of scam types/categories.
    """
    conn = get_db()
    cursor = conn.cursor()

    days = request.args.get("days", 30, type=int)
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    cursor.execute("""
        SELECT category, COUNT(*) as count,
               AVG(trust_score) as avg_trust_score,
               SUM(CASE WHEN risk_level IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) as critical_count
        FROM scam_incidents
        WHERE created_at > ?
        GROUP BY category
        ORDER BY count DESC
    """, (start_date,))

    results = cursor.fetchall()
    conn.close()

    category_data = [
        {
            "category": row["category"],
            "incident_count": row["count"],
            "avg_trust_score": row["avg_trust_score"],
            "critical_incidents": row["critical_count"],
            "percentage": 0
        }
        for row in results
    ]

    # Calculate percentages
    total = sum(c["incident_count"] for c in category_data)
    for category in category_data:
        category["percentage"] = round(
            (category["incident_count"] / total * 100) if total > 0 else 0,
            2
        )

    return jsonify({
        "success": True,
        "categories": category_data,
        "total_incidents": total,
        "time_range_days": days,
        "generated_at": str(datetime.utcnow())
    })


@dashboard_bp.route("/api/company-reputation", methods=["GET"])
def get_company_reputation():
    """
    Get company reputation scores based on recruiter reports.
    """
    conn = get_db()
    cursor = conn.cursor()

    limit = request.args.get("limit", 50, type=int)

    cursor.execute("""
        SELECT company_name, COUNT(*) as report_count,
               AVG(trust_score) as avg_trust_score,
               SUM(CASE WHEN risk_level IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) as critical_count,
               GROUP_CONCAT(DISTINCT recruiter_email, ', ') as recruiters
        FROM scam_incidents
        WHERE company_name IS NOT NULL
        GROUP BY company_name
        ORDER BY report_count DESC
        LIMIT ?
    """, (limit,))

    results = cursor.fetchall()
    conn.close()

    company_data = [
        {
            "company_name": row["company_name"],
            "report_count": row["report_count"],
            "avg_trust_score": row["avg_trust_score"],
            "critical_incidents": row["critical_count"],
            "reputation_status": "BLACKLISTED" if row["critical_count"] > 5 else (
                "FLAGGED" if row["critical_count"] > 0 else "UNDER REVIEW"
            ),
            "recruiters_involved": row["recruiters"].split(", ") if row["recruiters"] else []
        }
        for row in results
    ]

    return jsonify({
        "success": True,
        "companies": company_data,
        "total_companies": len(company_data),
        "generated_at": str(datetime.utcnow())
    })


# ============================================================
# APPEAL & JUDGMENT TRACKING
# ============================================================

@dashboard_bp.route("/api/appeal/create", methods=["POST"])
def create_appeal():
    """
    Create an appeal case for judge review.
    Requires: victim_email, incident_id, appeal_reason, evidence
    """
    data = request.get_json()

    required_fields = ["victim_email", "incident_id", "appeal_reason", "evidence"]
    if not all(field in data for field in required_fields):
        return jsonify({
            "success": False,
            "error": "Missing required fields"
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO appeal_cases
        (victim_email, incident_id, appeal_reason, evidence, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        data["victim_email"],
        data["incident_id"],
        data["appeal_reason"],
        json.dumps(data["evidence"]),
        "PENDING",
        str(datetime.utcnow())
    ))

    appeal_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "appeal_id": appeal_id,
        "status": "PENDING",
        "message": "Appeal case created successfully"
    })


@dashboard_bp.route("/api/appeal/<int:appeal_id>", methods=["GET"])
def get_appeal(appeal_id):
    """
    Get appeal case details.
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM appeal_cases WHERE id = ?
    """, (appeal_id,))

    appeal = cursor.fetchone()
    conn.close()

    if not appeal:
        return jsonify({
            "success": False,
            "error": "Appeal not found"
        }), 404

    return jsonify({
        "success": True,
        "appeal": {
            "id": appeal["id"],
            "victim_email": appeal["victim_email"],
            "incident_id": appeal["incident_id"],
            "appeal_reason": appeal["appeal_reason"],
            "evidence": json.loads(appeal["evidence"]),
            "status": appeal["status"],
            "judge_notes": appeal["judge_notes"],
            "created_at": appeal["created_at"],
            "resolved_at": appeal["resolved_at"],
            "resolution": appeal["resolution"]
        }
    })


@dashboard_bp.route("/api/appeal/<int:appeal_id>/judge-review", methods=["POST"])
def judge_review_appeal(appeal_id):
    """
    Judge reviews and resolves appeal case.
    Requires: judge_notes, resolution (APPROVED/REJECTED/PENDING)
    """
    data = request.get_json()

    if not data.get("resolution") or data["resolution"] not in ["APPROVED", "REJECTED", "PENDING"]:
        return jsonify({
            "success": False,
            "error": "Invalid resolution status"
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    resolved_at = str(datetime.utcnow()) if data["resolution"] != "PENDING" else None

    cursor.execute("""
        UPDATE appeal_cases
        SET status = ?, judge_notes = ?, resolved_at = ?, resolution = ?
        WHERE id = ?
    """, (
        data["resolution"],
        data.get("judge_notes", ""),
        resolved_at,
        data["resolution"],
        appeal_id
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "appeal_id": appeal_id,
        "status": data["resolution"],
        "resolved_at": resolved_at,
        "message": "Appeal reviewed successfully"
    })


@dashboard_bp.route("/api/appeal/list", methods=["GET"])
def list_appeals():
    """
    List all appeal cases with filtering options.
    Query params: status (PENDING/APPROVED/REJECTED), limit, sort_by
    """
    conn = get_db()
    cursor = conn.cursor()

    status = request.args.get("status", "PENDING")
    limit = request.args.get("limit", 50, type=int)
    sort_by = request.args.get("sort_by", "created_at DESC")

    query = f"""
        SELECT id, victim_email, incident_id, appeal_reason, status,
               judge_notes, created_at, resolved_at, resolution
        FROM appeal_cases
        WHERE status = ?
        ORDER BY {sort_by}
        LIMIT ?
    """

    cursor.execute(query, (status, limit))
    appeals = cursor.fetchall()
    conn.close()

    appeals_data = [
        {
            "id": row["id"],
            "victim_email": row["victim_email"],
            "incident_id": row["incident_id"],
            "appeal_reason": row["appeal_reason"],
            "status": row["status"],
            "judge_notes": row["judge_notes"],
            "created_at": row["created_at"],
            "resolved_at": row["resolved_at"],
            "resolution": row["resolution"]
        }
        for row in appeals
    ]

    return jsonify({
        "success": True,
        "appeals": appeals_data,
        "total_count": len(appeals_data),
        "status_filter": status,
        "generated_at": str(datetime.utcnow())
    })


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

@dashboard_bp.route("/api/summary", methods=["GET"])
def get_dashboard_summary():
    """
    Get comprehensive dashboard summary.
    Includes key metrics, trends, and alerts.
    """
    conn = get_db()
    cursor = conn.cursor()

    days = request.args.get("days", 30, type=int)
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()

    # Overall statistics
    cursor.execute("""
        SELECT COUNT(*) as total_incidents,
               AVG(trust_score) as avg_trust_score,
               MIN(trust_score) as min_trust_score,
               MAX(trust_score) as max_trust_score
        FROM scam_incidents
        WHERE created_at > ?
    """, (start_date,))

    overall = cursor.fetchone()

    # Risk distribution
    cursor.execute("""
        SELECT risk_level, COUNT(*) as count
        FROM scam_incidents
        WHERE created_at > ?
        GROUP BY risk_level
    """, (start_date,))

    risk_dist = {row["risk_level"]: row["count"] for row in cursor.fetchall()}

    # Top platforms
    cursor.execute("""
        SELECT platform, COUNT(*) as count
        FROM scam_incidents
        WHERE created_at > ?
        GROUP BY platform
        ORDER BY count DESC
        LIMIT 5
    """, (start_date,))

    top_platforms = [{"platform": row["platform"], "count": row["count"]} for row in cursor.fetchall()]

    # Top countries
    cursor.execute("""
        SELECT country, COUNT(*) as count
        FROM scam_incidents
        WHERE country IS NOT NULL AND created_at > ?
        GROUP BY country
        ORDER BY count DESC
        LIMIT 5
    """, (start_date,))

    top_countries = [{"country": row["country"], "count": row["count"]} for row in cursor.fetchall()]

    # Recruiter statistics
    cursor.execute("""
        SELECT COUNT(*) as total_recruiters,
               SUM(CASE WHEN status = 'FLAGGED' THEN 1 ELSE 0 END) as flagged_count,
               SUM(CASE WHEN status = 'VERIFIED' THEN 1 ELSE 0 END) as verified_count,
               AVG(trust_score) as avg_trust_score
        FROM recruiter_profiles
    """)

    recruiter_stats = cursor.fetchone()

    # Appeal statistics
    cursor.execute("""
        SELECT status, COUNT(*) as count
        FROM appeal_cases
        GROUP BY status
    """)

    appeal_dist = {row["status"]: row["count"] for row in cursor.fetchall()}

    conn.close()

    return jsonify({
        "success": True,
        "summary": {
            "total_incidents": overall["total_incidents"],
            "average_trust_score": round(overall["avg_trust_score"], 2) if overall["avg_trust_score"] else 50,
            "min_trust_score": overall["min_trust_score"],
            "max_trust_score": overall["max_trust_score"],
            "risk_distribution": risk_dist,
            "top_platforms": top_platforms,
            "top_countries": top_countries,
            "recruiter_statistics": {
                "total_recruiters": recruiter_stats["total_recruiters"],
                "flagged_count": recruiter_stats["flagged_count"],
                "verified_count": recruiter_stats["verified_count"],
                "average_trust_score": round(recruiter_stats["avg_trust_score"], 2) if recruiter_stats["avg_trust_score"] else 50
            },
            "appeal_statistics": appeal_dist
        },
        "time_range_days": days,
        "generated_at": str(datetime.utcnow())
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@dashboard_bp.route("/health", methods=["GET"])
def dashboard_health():
    return jsonify({
        "status": "running",
        "module": "Dashboard Analytics"
    })
