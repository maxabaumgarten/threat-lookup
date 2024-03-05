### A python script that performs IP lookups against threat intel platforms and returns the results in a human-readable format.
# User passes in an IP address as an argument and the script returns the results from the following threat intel platforms:
# - GreyNoise
# - Shodan
# - VirusTotal
# - AlientVault OTX


import requests
import json
import ipaddress
from dotenv import load_dotenv
import os
import sys
import shodan

# Load environment variables
load_dotenv()

# GreyNoise API Key
GREYNOISE_API_KEY = gn_key = os.getenv("GN_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VT_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIEN_KEY")

# Function to perform IP lookup against GreyNoise
def gn_lookup(ip):
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

# Function to perform IP lookup against Shodan
def shodan_lookup(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        results = api.host(ip)
        return results
    except shodan.APIError as e:
        print(f"Error: {e}")

# Function to print the results of the Shodan IP lookup
def shodan_results(data):
    if data is None:
        print("No results found for this IP address.")
    else:
        try:
            print(f"Organization: {data['org']}")
            print(f"Operating System: {data['os']}")
            print(f"Ports: {data['ports']}")
            print(f"Hostnames: {data['hostnames']}")
            print(f"Last Update: {data['last_update']}")
        except KeyError:
            print("No results found for this IP address.")


# Function to perform IP lookup against VirusTotal
def vt_lookup(ip):
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

# Function to perform IP lookup against AlienVault OTX
def otx_lookup(ip):
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
        

# Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: main.py <ip_address>")
        sys.exit(1)
    ip = sys.argv[1]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Invalid IP address.")
        sys.exit(1)
    # Skip any api lookup if there is no API key and move to the next one
    if GREYNOISE_API_KEY:
        print(f"GreyNoise Results for {ip}:")
        gn_data = gn_lookup(ip)
        gn_results(gn_data)
        print()
    else:
        print("No GreyNoise API key found. Skipping GreyNoise lookup.")
    if SHODAN_API_KEY:
        print(f"Shodan Results for {ip}:")
        shodan_data = shodan_lookup(ip)
        shodan_results(shodan_data)
        print()
    else:
        print("No Shodan API key found. Skipping Shodan lookup.")
    if VIRUSTOTAL_API_KEY:
        print(f"VirusTotal Results for {ip}:")
        vt_data = vt_lookup(ip)
        vt_results(vt_data)
        print()
    else:
        print("No VirusTotal API key found. Skipping VirusTotal lookup.")
    if ALIENVAULT_API_KEY:
        print(f"AlienVault OTX Results for {ip}:")
        otx_data = otx_lookup(ip)
        otx_results(otx_data)
        print()
    else:
        print("No AlienVault OTX API key found. Skipping AlienVault OTX lookup.")

if __name__ == "__main__":
    main()


