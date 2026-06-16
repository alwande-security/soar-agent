import ollama
import json
from tools.virustotal import check_ip, check_hash, check_domain

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

    # Step 1 — Tell the AI what it is and what tools it has
    system_prompt = """You are a SOC analyst AI agent. 
When you receive a security alert, you investigate it by calling tools.

You have access to these tools:
- check_ip(ip) — checks an IP address on VirusTotal
- check_hash(hash) — checks a file hash on VirusTotal  
- check_domain(domain) — checks a domain on VirusTotal

To call a tool, respond with ONLY this exact format:
TOOL: check_ip
INPUT: 185.220.101.47

When you have enough information to make a verdict, respond with:
VERDICT: [your final analysis and severity score out of 10]

Investigate step by step. Call one tool at a time."""

    # Step 2 — Build the conversation history
    messages = [
        {
            "role": "user",
            "content": f"System: {system_prompt}\n\nNew alert to investigate: {alert}"
        }
    ]

    # Step 3 — The agent loop (max 5 steps so it doesn't run forever)
    for step in range(5):
        print(f"--- Step {step + 1} ---")

        # Ask the AI what to do next
        response = ollama.chat(
            model="tinyllama",
            messages=messages
        )

        ai_response = response["message"]["content"]
        print(f"AI: {ai_response}\n")

        # Add AI response to conversation history
        messages.append({
            "role": "assistant",
            "content": ai_response
        })

        # Step 4 — Check if AI wants to call a tool
        if "TOOL:" in ai_response and "INPUT:" in ai_response:
            
            # Extract tool name and input
            lines = ai_response.strip().split("\n")
            tool_name = ""
            tool_input = ""
            
            for line in lines:
                if line.startswith("TOOL:"):
                    tool_name = line.replace("TOOL:", "").strip()
                if line.startswith("INPUT:"):
                    tool_input = line.replace("INPUT:", "").strip()

            print(f">>> Calling tool: {tool_name}({tool_input})")

            # Step 5 — Actually call the tool
            if tool_name == "check_ip":
                result = check_ip(tool_input)
            elif tool_name == "check_hash":
                result = check_hash(tool_input)
            elif tool_name == "check_domain":
                result = check_domain(tool_input)
            else:
                result = {"error": "Unknown tool"}

            print(f">>> Tool result: {result}\n")

            # Step 6 — Feed the result back to the AI
            messages.append({
                "role": "user",
                "content": f"Tool result: {json.dumps(result)}\n\nContinue your investigation."
            })

        # Step 7 — Check if AI has reached a verdict
        elif "VERDICT:" in ai_response:
            print("\n" + "="*50)
            print("INVESTIGATION COMPLETE")
            print("="*50)
            return ai_response

    return "Agent reached maximum steps without verdict."