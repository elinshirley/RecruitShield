scam_history = {
    "Telegram": [5, 8, 12, 18, 25, 40],
    "WhatsApp": [10, 15, 20, 28, 35, 45],
    "LinkedIn": [3, 4, 5, 6, 8, 10],
    "Email": [2, 3, 4, 5, 6, 7]
}
def predict_scam_risk(platform):

    data = scam_history.get(platform)

    if not data:
        return "Unknown"

    growth = data[-1] - data[-2]

    if growth > 10:
        return "Very High"

    elif growth > 5:
        return "High"

    elif growth > 2:
        return "Medium"

    return "Low"