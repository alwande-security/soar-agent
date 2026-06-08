# AI-Powered SOAR Prototype

An AI agent that automates SOC analyst workflows — enriching IOCs 
via threat intel APIs and mapping findings to MITRE ATT&CK.

## Built with
- Python
- Amazon Bedrock (Claude)
- VirusTotal API
- MITRE ATT&CK
- AbuseIPDB

## Status
🚧 In active development

## Architecture
- `main.py` — entry point
- `agent.py` — orchestrator loop (observe → think → act)
- `tools/` — threat intel API integrations

## Stages
- [x] Stage 1 — Project setup
- [x] Stage 2 — Bedrock connection
- [x] Stage 3 — VirusTotal tool
- [ ] Stage 4 — Agent loop
- [ ] Stage 5 — Additional tools
- [ ] Stage 6 — Dashboard
