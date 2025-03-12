import requests
from config.settings import SLACK_WEBHOOK_URL

def send_slack_alert(message):
    data = {"text": message}
    response = requests.post(SLACK_WEBHOOK_URL, json=data)
    return response.status_code

if __name__ == "__main__":
    send_slack_alert("⚠️ High-severity threat detected!")
