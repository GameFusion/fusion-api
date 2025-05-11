from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Retrieve the Slack token from environment variables
slack_token = os.getenv("SLACK_BOT_TOKEN")

def send_slack_notification(token, channel, message):
    client = WebClient(token=token)

    try:
        response = client.chat_postMessage(
            channel=channel,
            text=message
        )
        print(f"Message sent to {channel}: {response['message']['text']}")
    except SlackApiError as e:
        print(f"Error sending message: {e.response['error']}")

def post(channel, message):
    send_slack_notification(slack_token, channel, message)

if __name__ == "__main__":
    # Channel ID or name (e.g., '#general' or 'C1234567890')
    channel = "#general"
    channel = "#cbp-api"

    # Your message
    message = "Hello, this is a test notification from Python from cbpapi.com!"

    send_slack_notification(slack_token, channel, message)

