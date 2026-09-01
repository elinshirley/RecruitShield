# 🛡️ RecruitShield AI

### AI-Powered Recruitment Scam Detection & Recruiter Verification Platform

<p align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge\&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Web_App-red?style=for-the-badge\&logo=streamlit)
![SQLite](https://img.shields.io/badge/SQLite-Database-green?style=for-the-badge\&logo=sqlite)
![Blockchain](https://img.shields.io/badge/Blockchain-Scam_Registry-orange?style=for-the-badge)
![AI Powered](https://img.shields.io/badge/AI-Powered-purple?style=for-the-badge)
![Hackathon Project](https://img.shields.io/badge/Hackathon-Project-gold?style=for-the-badge)

</p>

---

# 📌 Overview

RecruitShield AI is an intelligent recruitment fraud detection platform designed to protect job seekers from fake recruiters, fraudulent job postings, phishing attempts, and employment scams.

The platform combines:

* AI-driven trust scoring
* Recruiter identity verification
* Domain intelligence analysis
* Community-powered scam reporting
* Blockchain-based scam registry
* Predictive fraud analytics
* Real-time risk assessment

RecruitShield analyzes recruitment messages, emails, job advertisements, recruiter information, and company details to determine whether an opportunity is legitimate or potentially fraudulent.

The system provides transparent explanations for every risk decision, helping users understand why a job offer may be dangerous.

---

# 🚨 Problem Statement

Online recruitment fraud is growing rapidly across platforms such as:

* LinkedIn
* Telegram
* WhatsApp
* Email
* Job portals

Common scam tactics include:

* Fake recruiters
* Advance fee scams
* Registration fee fraud
* Identity theft
* Phishing websites
* Fake interview invitations
* Fraudulent work-from-home schemes

Millions of job seekers are targeted every year, often losing money or sensitive personal information.

Most users lack the technical expertise to verify:

* Recruiter authenticity
* Company legitimacy
* Website trustworthiness
* Domain ownership
* Scam patterns

RecruitShield addresses these challenges through automated fraud detection and verification.

---

# 🎯 Solution

RecruitShield acts as an intelligent recruitment safety assistant.

Users simply provide:

* Job posting text
* Recruiter email
* Company website
* LinkedIn profile
* Platform source

The system performs multiple verification checks and generates a Trust Score from 0–100.

It then provides:

* Risk assessment
* Red flag explanations
* Safety recommendations
* Recruiter verification status

---

# 🏗️ System Architecture

```text
                    ┌────────────────────┐
                    │  Job Posting Input │
                    └─────────┬──────────┘
                              │
                              ▼
                ┌───────────────────────────┐
                │ RecruitShield AI Engine   │
                └─────────┬─────────────────┘
                          │
     ┌────────────────────┼────────────────────┐
     │                    │                    │
     ▼                    ▼                    ▼

Keyword Analysis    Identity Verification   Domain Intelligence

     │                    │                    │

     ▼                    ▼                    ▼

Fraud Prediction   LinkedIn Validation   WHOIS Analysis

     │                    │                    │

     ▼                    ▼                    ▼

Community Reports  Scam Registry Check  Blockchain Verification

                     │
                     ▼

             Trust Score Engine

                     │
                     ▼

          Explainable Risk Report

                     │
                     ▼

           Streamlit Dashboard
```

---

# ✨ Key Features

## 🧠 AI-Powered Trust Score Engine

RecruitShield calculates a comprehensive Trust Score based on multiple risk indicators.

### Analysis Factors

* Fraud keywords
* Scam language patterns
* Urgency tactics
* Recruiter identity
* Domain reputation
* Community reports
* Scam registry matches
* Emerging fraud trends

### Output

```text
Trust Score: 28/100

Verdict:
🔴 HIGH RISK

Recommendation:
Do not send money or personal documents.
```

---

## 🏢 Company & Recruiter Identity Verification

One of the strongest features of RecruitShield.

The system verifies whether:

* Recruiter email matches company domain
* Company website is valid
* LinkedIn profile appears legitimate
* Domain ownership is consistent

### Example

Recruiter Email

[hr.microsoft.jobs@gmail.com](mailto:hr.microsoft.jobs@gmail.com)

Company Website

microsoft.com

Result

❌ Domain Mismatch

Risk Increased

Potential Impersonation Detected

---

## 🌐 Domain Intelligence Engine

RecruitShield performs WHOIS-based domain investigations.

Checks include:

* Domain age
* Registrar information
* Domain ownership consistency

### Example

Website:

new-tech-careers.com

Registered:

10 days ago

Result:

🚨 High Risk

Reason:

Recently registered domains are commonly used in recruitment scams.

---

## ⛓️ Blockchain-Anchored Scam Registry

RecruitShield stores confirmed scam reports in an immutable blockchain structure.

Benefits:

* Tamper-resistant records
* Evidence preservation
* Transparent verification
* Historical traceability

Every confirmed report is:

1. Hashed
2. Added to blockchain
3. Linked to previous block
4. Permanently recorded

---

## 👥 Community-Powered Crowdsourcing

Users can submit scam reports that strengthen protection for everyone.

Community reports help:

* Identify repeat offenders
* Detect fake recruiters
* Build scam intelligence
* Warn future victims

This creates a collaborative fraud prevention network.

---

## 📈 Predictive Fraud Analytics

RecruitShield does not only detect current scams.

It predicts future fraud risks.

The predictive engine identifies:

* Scam spikes
* Platform-specific threats
* Emerging recruitment fraud trends

Example:

| Platform | Risk      |
| -------- | --------- |
| LinkedIn | Medium    |
| Email    | High      |
| Telegram | Very High |

---

## 🔄 Automated Scam Pattern Updates

Fraud tactics evolve constantly.

RecruitShield automatically updates:

* Scam indicators
* Detection patterns
* Risk models

This enables adaptation to:

* New payment scams
* New messaging tactics
* New impersonation methods
* Emerging recruitment fraud schemes

---

## 🚩 Explainable AI

Unlike traditional black-box systems, RecruitShield explains every decision.

Example:

```text
HIGH RISK

Reason:
Registration fee detected.

Penalty:
-25 points
```

Users receive transparent reasoning behind every warning.

---

## 📊 Analytics Dashboard

The integrated dashboard provides:

### Incident Monitoring

* Total incidents
* Critical scam reports
* Trust score trends

### Recruiter Intelligence

* Flagged recruiters
* Company statistics
* Platform analysis

### Fraud Visualization

* Risk distribution
* Platform comparison
* Historical trends

---

# 🖥️ User Workflow

```text
User Inputs Job Posting
          │
          ▼
Trust Score Analysis
          │
          ▼
Identity Verification
          │
          ▼
Scam Registry Check
          │
          ▼
Risk Assessment
          │
          ▼
Recommendations Generated
          │
          ▼
Dashboard & Reports
```

---

# 📂 Project Structure

[text](docker-compose.yml) 
[text](dockerfile) 
[text](fraud_predictor.py) 
[text](main.py) 
[text](nginx.conf) 
[text](pattern_updater.py)
[text](README.md) 
[text](RecruitShield.pdf)
 [text](requirements.txt) 
 [text](runtime.txt) 
 [text](<scam detection.pptx>)
  [text](scam_blockchain.json) 
  [text](scamshield.db) 
  [text](telegram_bot.py)
   [text](test_api.py) 
   [text](test_blockchain.py)
    [text](__pycache__)
     [text](browser_extension)
      [text](.env) 
      [text](.gitattributes) 
      [text](community_reports.json)
       [text](crowd_reports.py) 
       [text](dashboard.py)

---

# 🛠️ Technology Stack

| Category        | Technology            |
| --------------- | --------------------- |
| Frontend        | Streamlit             |
| Backend         | Python                |
| Database        | SQLite                |
| Web Scraping    | BeautifulSoup         |
| Domain Analysis | WHOIS                 |
| AI Logic        | Custom Risk Engine    |
| Blockchain      | SHA-256 Linked Blocks |
| Visualization   | Plotly                |
| APIs            | Requests              |


---

# ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/elinshirley/recruitshield.git

cd recruitshield
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
streamlit run main.py
```

---

# 📊 Impact Metrics

RecruitShield helps:

✅ Detect fraudulent recruiters

✅ Prevent financial losses

✅ Protect personal information

✅ Verify company legitimacy

✅ Identify emerging scams

✅ Build community scam intelligence

---

# 🚀 Future Roadmap

### Phase 1

* Browser Extension
* Mobile Application
* Dark Theme Dashboard

### Phase 2

* NLP-based scam classification
* Machine Learning risk scoring
* Global recruiter reputation database

### Phase 3

* Real blockchain deployment
* Enterprise dashboard
* Job portal integration APIs

---

# 🌍 Potential Applications

* Universities
* Placement Cells
* Job Portals
* HR Platforms
* Government Agencies
* Cybersecurity Organizations

---

# 👨‍💻 Team

### Team Name

Alpha Coders

### Project

RecruitShield AI

### Domain

Cybersecurity • Fraud Detection • Trust & Safety

---

# 🏆 Innovation Highlights

✔ AI-Powered Trust Scoring

✔ Recruiter Identity Verification

✔ Blockchain Scam Registry

✔ Community Crowdsourcing

✔ Predictive Fraud Analytics

✔ Explainable AI Decisions

✔ Real-Time Scam Detection

✔ Multi-Platform Protection

---

# 📜 License

This project is developed for educational, research, cybersecurity awareness, and hackathon purposes.

---

<p align="center">

🛡️ Protecting Job Seekers from Recruitment Fraud Through AI, Analytics, and Trust Verification.

</p>
