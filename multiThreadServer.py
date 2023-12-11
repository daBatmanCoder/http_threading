import random
import string
import base64
import socketserver
from jsonrpcserver import Error, Result, dispatch, method, serve, Success
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from web3 import Web3
import json
import threading
import http.server
import threading
import queue
import json
import requests
import time

polygon_url = "https://polygon-mumbai-bor.publicnode.com"
w3 = Web3(Web3.HTTPProvider(polygon_url))

contract_abi_small = [
    {
        "constant": True,
        "inputs": [
            {
                "name": "_tokenId",
                "type": "uint256"
            }
        ],
        "name": "tokenURI",
        "outputs": [
            {
                "name": "",
                "type": "string"
            }
        ],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [
            {
                "name": "_tokenId",
                "type": "uint256"
            }
        ],
        "name": "ownerOf",
        "outputs": [
            {
                "name": "",
                "type": "address"
            }
        ],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    }
]

def get_public_key(identity):

    contract_address = identity[0:42]
    token_id = identity[42:]

    identity_contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=contract_abi_small)
    token_uri = identity_contract.functions.tokenURI(int(token_id)).call()
    token_uri_json = json.loads(token_uri)

    public_key_value = None
    
    # Iterate through the attributes to find the one with 'trait_type' as 'public_key'
    for attribute in token_uri_json['attributes']:
        if attribute.get('trait_type') == 'public_key':
            public_key_value = attribute.get('value')
            print(public_key_value)
            break

    return public_key_value
  
  
def get_owner_of_nft(nft):

    contract_address = nft[0:42]
    token_id = nft[42:]

    identity_contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=contract_abi_small)
    addressOfOwner = identity_contract.functions.ownerOf(int(token_id)).call()
    
    return addressOfOwner

  
def generate_username_password():
    # Define the character set for the username and password
    char_set = string.ascii_letters + string.digits  # A-Z, a-z, 0-9

    # Define the length of the username and password
    username_length = random.randint(16, 20)  # Random length between 10 and 16
    password_length = random.randint(20, 24)  # Random length between 12 and 16

    # Generate the username and password
    username = ''.join(random.choice(char_set) for _ in range(username_length))
    password = ''.join(random.choice(char_set) for _ in range(password_length))

    print("Generated username and password: " + username + " " + password)

    #return username + ":" + password
    return f"{username}:{password}" # For now override

@method
def provide_encrypted_credentials(identity, ens)  -> str:
    
    public_key = serialization.load_pem_public_key(
        get_public_key(identity).encode(),
        backend=default_backend()
    )
        
    credentials = generate_username_password() 
    
    encrypted_credentials = public_key.encrypt(
                credentials.encode(),
                padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                    label=None
                )
    )
    
    assigned_credentials = credentials + ":" + str(base64.standard_b64encode(encrypted_credentials), encoding='utf-8')

    print("assigned " + assigned_credentials)
    
    
    return Success(assigned_credentials)


@method
def send_notification(ens):
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

class ThreadedTCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""

class ThreadedHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Process the request
        response_data = self.process_request(post_data)

        # Send a response back to the client
        self.send_response(200)  # 200 OK
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {"status": "received"}
        self.wfile.write(json.dumps(response_data).encode('utf-8'))

    def process_request(self, request_data):
        try:
            # Parse the request data
            data = json.loads(request_data)

            function_name = data.get("function")
            
            if function_name == "provide_encrypted_credentials":

                identity = data['identity']
                ens = data['ens']

                response_data = provide_encrypted_credentials(identity, ens)

            elif function_name == "send_notification":

                ens = data['ens']

                response_data = send_notification(ens)
            else:

                response_data = {"error": "Unknown function"}
                
            return (self.client_address, response_data)

        except json.JSONDecodeError:
            return "error"


if __name__ == "__main__":

    server_address = ('localhost', 5000)
    httpd = ThreadedTCPServer(server_address, ThreadedHTTPRequestHandler)
    print("Serving HTTP on localhost port 5000...")

    # Start a thread with the server -- that thread will then start one more thread for each request
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.start()
