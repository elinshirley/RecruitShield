import json
import os

REPORT_DB = "community_reports.json"

def load_reports():
    if not os.path.exists(REPORT_DB):
        return []
    with open(REPORT_DB, "r") as f:
        return json.load(f)

def save_report(company, reason):
    reports = load_reports()

    reports.append({
        "company": company.lower(),
        "reason": reason
    })

    with open(REPORT_DB, "w") as f:
        json.dump(reports, f, indent=4)

def check_company_reports(company):
    reports = load_reports()

    matches = [
        r for r in reports
        if r["company"] == company.lower()
    ]

    return matches