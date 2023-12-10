import http.server
import threading
import queue
import json
import requests
import time

# Global queue for storing results
result_queue = queue.Queue()

def function_1(data):
    time.sleep(5)
    # Logic for function_1
    return {"result": "Function 1 processed " + str(data)}

def function_2(data):
    time.sleep(5)
    # Logic for function_2
    return {"result": "Function 2 processed" + str(data)}


class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Without threading
        # self.process_request(post_data)

        # Spawn a new thread to process the request
        processing_thread = threading.Thread(target=self.process_request, args=(post_data,))
        processing_thread.start()

        # Send a response back to the client
        self.send_response(200)  # 200 OK
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {"status": "received"}
        self.wfile.write(json.dumps(response).encode('utf-8'))

    def process_request(self, request_data):
        # Parse the request data
        try:
            data = json.loads(request_data)
            function_name = data.get("function")

            if function_name == "function_1":
                response_data = function_1(data)
            elif function_name == "function_2":
                response_data = function_2(data)
            else:
                response_data = {"error": "Unknown function"}

            result_queue.put((self.client_address, response_data))
        except json.JSONDecodeError:
            result_queue.put((self.client_address, {"error": "Invalid JSON"}))


def result_processor():
    while True:
        client_address, response_data = result_queue.get()
        if response_data is None:  # Use a sentinel value to shut down the thread
            return
        # Process the result (e.g., log it, use it in some way)
        print(f"Processed result for {client_address}: {response_data}")

        # For testing the result queue efficiency 
        #time.sleep(3)


def send_request(ens):
    url = "https://us-central1-fir-b0db2.cloudfunctions.net/notification_server_py" # Sends the user the notification if the device is not registered
    payload = { 'ens': ens }

    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()  # This will raise an HTTPError if the HTTP request returned an unsuccessful status code
        print("Response Status:", response.status_code)
        print("Response Text:", response.text)
    except requests.exceptions.HTTPError as err:
        print("HTTP Error:", err)
        return "0"
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return "0"
    
    return "1"

if __name__ == "__main__":

    httpd = http.server.HTTPServer(('localhost', 8080), SimpleHTTPRequestHandler)

    for _ in range(5):
        worker_thread = threading.Thread(target=result_processor)
        worker_thread.start()


    print("Serving HTTP on localhost port 8080...")
    # Run the server
    httpd.serve_forever()
