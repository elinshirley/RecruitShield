import requests
import json

data = {
    "content": """
    Congratulations! You have been selected for a job.

    Pay a refundable security deposit of Rs. 5,000
    immediately to confirm your job.

    No interview required.
    Guaranteed job.
    """,

    "source": "WhatsApp",

    "category": "Recruitment Scam",

    "confidence": 95
}

response = requests.post(
    "http://127.0.0.1:5000/api/report-scam",
    json=data
)

print(json.dumps(
    response.json(),
    indent=4
))