from agent import run_agent

# Simulate an incoming alert
alert = {
    "type": "Suspicious outbound connection",
    "src_ip": "192.168.1.42",
    "dst_ip": "185.220.101.47",
    "port": 443,
    "repeat_count": 24
}

# Run the agent
run_agent(alert)