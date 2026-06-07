from dotenv import load_dotenv
import boto3
import json

# Load environment variables
load_dotenv()

# Create a Bedrock client — this is your connection to AWS Bedrock
client = boto3.client(
    service_name="bedrock-runtime",
    region_name="us-east-1"
)

# The model we want to use
MODEL_ID = "us.anthropic.claude-sonnet-4-20250514-v1:0"

# The message we're sending
message = "You are a SOC analyst assistant. A suspicious IP address 185.220.101.47 has been flagged. What do you know about this type of IP?"

# Format the request
request_body = {
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 1024,
    "messages": [
        {
            "role": "user",
            "content": message
        }
    ]
}

# Send the request to Bedrock
response = client.invoke_model(
    modelId=MODEL_ID,
    body=json.dumps(request_body)
)

# Read and print the response
response_body = json.loads(response["body"].read())
print(response_body["content"][0]["text"])