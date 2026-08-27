import requests

data = {
    "content": """
    Congratulations! You are selected for an immediate job.

    Pay a refundable security deposit and registration fee
    of Rs. 5,000 immediately.

    No interview required.
    Guaranteed job.

    Contact us urgently on WhatsApp.
    """,
    "source": "manual"
}

response = requests.post(
    "http://127.0.0.1:5000/api/analyze",
    json=data
)

print(response.json())