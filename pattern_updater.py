scam_patterns = [
    "registration fee",
    "processing fee",
    "pay to apply",
    "training deposit",
    "advance payment"
]


def update_patterns():
    """Update scam patterns with new emerging threats."""
    new_patterns = [
        "wallet activation charge",
        "crypto verification payment",
        "security verification fee",
        "refundable deposit"
    ]

    scam_patterns.extend(new_patterns)


def detect_new_scam_pattern(text):
    """
    Detect if text contains known scam patterns.
    
    Args:
        text (str): Text to analyze
        
    Returns:
        bool: True if scam pattern detected, False otherwise
    """
    if not text:
        return False
    
    text = text.lower()

    for pattern in scam_patterns:
        if pattern in text:
            return True

    return False
