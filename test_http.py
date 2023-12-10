import requests
import json
import threading

# URL of the local server
url = 'http://localhost:8080'

# Function to send a request to the server
def send_request(function_name, additional_data):
    data = {
        'function': function_name,
        **additional_data
    }
    response = requests.post(url, json=data)
    print(f"Response from server for {function_name}:")
    print(response.text)

def send_concurrent_requests():
    threads = []
    for i in range(5):  # Send 5 requests
        t = threading.Thread(target=send_request, args=(f'function_{i%2 + 1}', {'data': i}))
        threads.append(t)
        t.start()

send_concurrent_requests()
