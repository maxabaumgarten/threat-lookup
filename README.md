# threat-lookup
Quickly look up threat actor IPs against Threat Intel APIs with Free tiers

## What is this for?
- Your org doesnt pay for Threat intel feeds and you have an Actor IP you want to lookup quickly
- Removes the need to visit multiple threat intel sites

## **Current Sources**
- [GreyNoise](https://www.greynoise.io/)
- [AlienVault](otx.alienvault.com)
- [Shodan](shodan.io)
- [VirusTotal](https://virustotal.com/)

## Instructions
- Install python packages: ```pip install -r requirements.txt```
- Modify `.env` files with your API Keys
  - Ideally these should be stored in a secrets manager
- `python main.py <IP-ADDRESS>`

