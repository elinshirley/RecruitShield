scam_patterns = [
    "registration fee",
    "processing fee",
    "pay to apply",
    "training deposit",
    "advance payment"
]
def update_patterns():

    new_patterns = [
        "wallet activation charge",
        "crypto verification payment",
        "security verification fee",
        "refundable deposit"
    ]

    scam_patterns.extend(new_patterns)

def detect_new_scam_patterns(text):

    text = text.lower()

    for pattern in scam_patterns:

        if pattern in text:
            return True

    return False