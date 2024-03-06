### A python script that performs IP lookups against threat intel platforms and returns the results in a human-readable format.
# User passes in an IP address as an argument and the script returns the results from the following threat intel platforms:
# - GreyNoise
# - Shodan
# - VirusTotal
# - AlientVault OTX

import ipaddress
import sys
from greynoise import gn_lookup, gn_results
from shodan_function import shodan_lookup, shodan_results
from virustotal import vt_lookup, vt_results
from alienvault import otx_lookup, otx_results


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

    gn_query = gn_lookup(ip)
    if gn_query is not None:
        print(f"\nGreyNoise Results for {ip}:")
        gn_results(gn_query)
        print()
    else:
        print("No GreyNoise API key found. Skipping GreyNoise lookup.")

    shodan_query = shodan_lookup(ip)
    if shodan_query is not None:
        print(f"\nShodan Results for {ip}:")
        shodan_results(shodan_query)
        print()
    else:
        print("No Shodan API key found. Skipping Shodan lookup.")

    vt_query = vt_lookup(ip)
    if vt_query is not None:
        print(f"\nVirusTotal Results for {ip}:")
        vt_results(vt_query)
        print()
    else:
        print("No VirusTotal API key found. Skipping VirusTotal lookup.")

    otx_query = otx_lookup(ip)
    if otx_query is not None:
        print(f"\nAlienVault OTX Results for {ip}:")
        otx_results(otx_query)
        print()
    else:
        print("No AlienVault OTX API key found. Skipping AlienVault OTX lookup.")

if __name__ == "__main__":
    main()


