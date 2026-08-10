import ollama

def generate_summary():
    # Simulated batch logs
    simulated_logs = "10:01 - Port scan detected from IP 192.168.1.50. 10:02 - Multiple failed SSH logins. 10:03 - IP 192.168.1.50 quarantined by Immune Core."
    
    response = ollama.chat(model='phi4-mini', messages=[
        {
            'role': 'system',
            'content': 'You are a SOC analyst. Summarize these logs into a 3-sentence incident report.'
        },
        {
            'role': 'user',
            'content': simulated_logs
        }
    ])
    print(response['message']['content'])

# Make sure the line below has 4 spaces before it!
if __name__ == "__main__":
    generate_summary()