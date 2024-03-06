import requests
import os
import json
from dotenv import load_dotenv

GREYNOISE_API_KEY = gn_key = os.getenv("GN_KEY")

# Function to perform IP lookup against GreyNoise
def gn_lookup(ip):
    if not GREYNOISE_API_KEY:
        print("No GreyNoise API key found.")
        return None
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {
        "accept": "application/json",
        "key": GREYNOISE_API_KEY
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    return data

# Function to print the results of the GN IP lookup
def gn_results(data):
    if data is None:
        print("No data returned from GreyNoise.")
    else:
        try:
            print(f"Noise: {data['noise']}")
            print(f"riot: {data['riot']}")
            print(f"Classification: {data['classification']}")
            print(f"Name: {data['name']}")
            print(f"Last Seen: {data['last_seen']}")
            print(f"Message: {data['message']}")
        except KeyError:
            print("No data returned from GreyNoise.")