# AI-Powered SOAR Prototype

An AI agent that automates SOC analyst workflows — enriching IOCs 
via threat intel APIs and mapping findings to MITRE ATT&CK.

## Built with
- Python
- Ollama (Mistral — local AI, no API costs)
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
- [x] Stage 2 — Local AI connected via Ollama/Mistral
- [x] Stage 3 — VirusTotal tool written
- [x] Stage 4 — Agent loop (wire AI + tools together)
- [x] Stage 5 — Additional tools (MITRE ATT&CK, AbuseIPDB)
- [ ] Stage 6 — Dashboard

## Note
Built using a local Mistral model via Ollama for development.
Designed to be portable to AWS Bedrock or Anthropic API for production deployment.
