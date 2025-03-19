from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

def send_slack_alert(message):
    client = WebClient(token="xoxb-your-slack-token")  # Replace with your Slack token
    try:
        response = client.chat_postMessage(channel="#cyber-threats", text=message)
        return response
    except SlackApiError as e:
        print(f"Error sending Slack alert: {e}")

if __name__ == "__main__":
    send_slack_alert("New phishing threat detected: example-fake.com")