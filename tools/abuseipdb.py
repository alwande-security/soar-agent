import requests
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip_abuse(ip_address):
    """Check an IP address against AbuseIPDB"""
    
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }
    
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "ip": ip_address,
            "abuse_score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "country": data["countryCode"],
            "isp": data["isp"],
            "verdict": "MALICIOUS" if data["abuseConfidenceScore"] > 50 else "CLEAN"
        }
    else:
        return {"error": f"AbuseIPDB returned {response.status_code}"}