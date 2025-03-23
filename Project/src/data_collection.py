import requests  # Import the requests library to make HTTP requests
from settings import ALIENVAULT_API_KEY  # Import API key from settings file

def fetch_alienvault_threats():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"  # API endpoint for fetching subscribed threat pulses
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}  # Set up API authentication using the API key

    # Send GET request to AlienVault API
    response = requests.get(url, headers=headers)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        return response.json()["results"]  # Extract and return the list of threat pulses

    return {}  # Return an empty dictionary if the request fails

if __name__ == "__main__":
    # Fetch and print the threat intelligence data
    threats = fetch_alienvault_threats()
    print(threats)
