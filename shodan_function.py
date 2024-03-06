import shodan
import os
from dotenv import load_dotenv

SHODAN_API_KEY = os.getenv("SHODAN_KEY")


# Function to perform IP lookup against Shodan
def shodan_lookup(ip):
    if not SHODAN_API_KEY:
        print("No Shodan API key found.")
        return None
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