import requests
import os
import json
from dotenv import load_dotenv

ALIENVAULT_API_KEY = os.getenv("ALIEN_KEY")

# Function to perform IP lookup against AlienVault OTX
def otx_lookup(ip):
    if not ALIENVAULT_API_KEY:
        print("No AlienVault OTX API key found.")
        return None
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": ALIENVAULT_API_KEY
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    return data

# Function to print the results of the AlienVault OTX IP lookup
def otx_results(data):
    if data is None:
        print("No data returned from AlienVault OTX.")
    else:
        print(f"# of Pulses: {data['pulse_info']['count']}")