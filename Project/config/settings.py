import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
IBM_XFORCE_API_KEY = os.getenv("IBM_XFORCE_API_KEY")
IBM_XFORCE_API_PASSWORD = os.getenv("IBM_XFORCE_API_PASSWORD")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
