import ollama

# The message we're sending
message = "You are a SOC analyst assistant. A suspicious IP address 185.220.101.47 has been flagged. What do you know about this type of IP?"

# Send message to local Mistral model
response = ollama.chat(
    model="mistral",
    messages=[
        {
            "role": "user",
            "content": message
        }
    ]
)

# Print the response
print(response["message"]["content"])