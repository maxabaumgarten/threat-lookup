### A python script that performs IP lookups against threat intel platforms and returns the results in a human-readable format.

import requests
import json
import ipaddress
from dotenv import load_dotenv
import os

