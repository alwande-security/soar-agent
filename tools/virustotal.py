import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

def check_hash(file_hash):
  """Checks a file hash against the VirusTotal"""
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
            "domain": domain,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"],
            "verdict": "malicious" if stats["malicious"] > 0 else "clean"
        }
    else:
        return {"error": f"Error checking hash: {response.status_code}"}
 