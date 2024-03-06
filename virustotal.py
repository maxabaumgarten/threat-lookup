import requests
import os
import json
from dotenv import load_dotenv

VIRUSTOTAL_API_KEY = os.getenv("VT_KEY")

# Function to perform IP lookup against VirusTotal
def vt_lookup(ip):
    if not VIRUSTOTAL_API_KEY:
        print("No VirusTotal API key found.")
        return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    return data

# Function to print the results of the VirusTotal IP lookup
def vt_results(data):
    if data is None:
        print("No data returned from VirusTotal.")
    else:
        try:
            attributes = data['data']['attributes']
            print(f"Last Analysis Stats: {attributes['last_analysis_stats']}")
            print(f"AS Owner: {attributes['as_owner']}")
            print(f"Reputation: {attributes['reputation']}")
            print(f"Continent: {attributes['continent']}")
        except KeyError as e:
            print(f"Expected data not found in VirusTotal response: {e}")