import ollama
import json
from tools.virustotal import check_ip, check_hash, check_domain
from tools.abuseipdb import check_ip_abuse
from tools.mitre import map_to_mitre

def run_agent(alert):
    """
    The agent loop — takes an alert, reasons about it,
    calls tools, and returns a final verdict.
    """

    print("\n" + "="*50)
    print("SOAR AGENT — NEW ALERT RECEIVED")
    print("="*50)
    print(f"Alert: {alert}")
    print("="*50 + "\n")

    system_prompt = """You are a SOC analyst AI agent.
You MUST investigate alerts by calling tools.
You ONLY have these tools available - do not invent others:

- check_ip
- check_hash
- check_domain
- check_ip_abuse
- map_to_mitre

RULES:
1. Call ONE tool at a time
2. Use EXACTLY this format, nothing else on the same line:
TOOL: check_ip
INPUT: 185.220.101.47

3. Wait for the tool result before calling another tool
4. After calling check_ip and check_ip_abuse, produce your VERDICT
5. Do NOT invent tools that are not listed above
6. Do NOT add any text on the same line as TOOL: or INPUT:

Start by calling check_ip on the destination IP."""

    messages = [
        {
            "role": "user",
            "content": f"System: {system_prompt}\n\nNew alert to investigate: {alert}"
        }
    ]

    for step in range(5):
        print(f"--- Step {step + 1} ---")

        response = ollama.chat(
            model="mistral",
            options={"num_ctx": 1024},
            messages=messages
        )

        ai_response = response["message"]["content"]
        print(f"AI: {ai_response}\n")

        messages.append({
            "role": "assistant",
            "content": ai_response
        })

        if "TOOL:" in ai_response and "INPUT:" in ai_response:
            lines = ai_response.strip().split("\n")
            tool_name = ""
            tool_input = ""

            for line in lines:
                if line.startswith("TOOL:"):
                    tool_name = line.replace("TOOL:", "").strip()
                if line.startswith("INPUT:"):
                    tool_input = line.replace("INPUT:", "").strip()

            print(f">>> Calling tool: {tool_name}({tool_input})")

            if tool_name == "check_ip":
                result = check_ip(tool_input)
            elif tool_name == "check_hash":
                result = check_hash(tool_input)
            elif tool_name == "check_domain":
                result = check_domain(tool_input)
            elif tool_name == "check_ip_abuse":
                result = check_ip_abuse(tool_input)
            elif tool_name == "map_to_mitre":
                result = map_to_mitre(tool_input)
            else:
                result = {"error": "Unknown tool"}

            print(f">>> Tool result: {result}\n")

            messages.append({
                "role": "user",
                "content": f"Tool result: {json.dumps(result)}\n\nContinue your investigation."
            })

        elif "VERDICT:" in ai_response:
            print("\n" + "="*50)
            print("INVESTIGATION COMPLETE")
            print("="*50)
            return ai_response

    return "Agent reached maximum steps without verdict."