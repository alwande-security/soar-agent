import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_hash(file_hash):
    """Check a file hash against VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "hash": file_hash,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"],
            "verdict": "MALICIOUS" if stats["malicious"] > 0 else "CLEAN"
        }
    else:
        return {"error": f"VirusTotal returned {response.status_code}"}


def check_ip(ip_address):
    """Check an IP address against VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "ip": ip_address,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"],
            "verdict": "MALICIOUS" if stats["malicious"] > 0 else "CLEAN"
        }
    else:
        return {"error": f"VirusTotal returned {response.status_code}"}


def check_domain(domain):
    """Check a domain against VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "ip": domain,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"],
            "verdict": "MALICIOUS" if stats["malicious"] > 0 else "CLEAN"
        }
    else:
        return {"error": f"VirusTotal returned {response.status_code}"}