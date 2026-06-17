import ollama

def map_to_mitre(alert_description):
    """
    Use the local AI to map alert behavior to MITRE ATT&CK techniques.
    No API key needed — uses your local Mistral model.
    """
    
    prompt = f"""You are a MITRE ATT&CK expert. 
Given this security alert, identify the most relevant MITRE ATT&CK techniques.

Alert: {alert_description}

Respond with ONLY a JSON object in this exact format, nothing else:
{{
    "techniques": [
        {{
            "id": "T1071",
            "name": "Application Layer Protocol",
            "tactic": "Command and Control"
        }}
    ],
    "summary": "one sentence explanation"
}}"""

    response = ollama.chat(
        model="mistral",
        options={{"num_ctx": 1024}},
        messages=[
            {{
                "role": "user",
                "content": prompt
            }}
        ]
    )
    
    return response["message"]["content"]