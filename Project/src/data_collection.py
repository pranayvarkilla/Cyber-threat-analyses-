import requests
from settings import ALIENVAULT_API_KEY

def fetch_alienvault_threats():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()["results"]
    return {}

if __name__ == "__main__":
    threats = fetch_alienvault_threats()
    print(threats)
