import os
from dotenv import load_dotenv

load_dotenv()

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)

# Import your existing scam detection functions
from main import analyze_content, format_bot_response


# --------------------------------------------------
# GET TOKEN FROM ENVIRONMENT VARIABLE
# --------------------------------------------------

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

if not BOT_TOKEN:
    raise ValueError(
        "TELEGRAM_BOT_TOKEN is not set. "
        "Set it before running the bot."
    )


# --------------------------------------------------
# START COMMAND
# --------------------------------------------------

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    message = """
🛡️ Welcome to Recruitment Scam Detector!

Send or forward me any suspicious:

• Job offer
• Recruitment message
• Email text
• WhatsApp message

I will analyze it and provide:

📊 Trust Score
🚩 Red Flags
🔍 Risk Verdict
💡 Safety Recommendations
"""

    await update.message.reply_text(message)


# --------------------------------------------------
# ANALYZE USER MESSAGE
# --------------------------------------------------

async def analyze_message(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    user_message = update.message.text

    if not user_message:
        await update.message.reply_text(
            "Please send me a text message to analyze."
        )
        return

    # Show processing message
    await update.message.reply_text(
        "🔍 Analyzing the message..."
    )

    try:

        # Use your existing function from main.py
        result = analyze_content(user_message)

        # Convert result to readable bot response
        reply = format_bot_response(result)

        # Send result back
        await update.message.reply_text(reply)

    except Exception as error:

        print("Analysis Error:", error)

        await update.message.reply_text(
            "❌ Something went wrong while analyzing the message."
        )


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    print("=" * 50)
    print("TELEGRAM SCAM DETECTOR BOT STARTING...")
    print("=" * 50)

    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .build()
    )

    # /start command
    app.add_handler(
        CommandHandler(
            "start",
            start
        )
    )

    # Handle normal text messages
    app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            analyze_message
        )
    )

    print("🤖 Telegram bot is running...")
    print("Press CTRL + C to stop.")

    # Start polling
    app.run_polling()


if __name__ == "__main__":
    main()