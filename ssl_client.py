import socket
import os
import sys
import ast
from rsa import generate_rsa_keys, encrypt, decrypt, text_to_int, int_to_text, generate_one_time_key, encode_packet, decode_packet

# Load user credentials from file
def load_user_credentials(file_path):
    credentials = {}
    try:
        with open(file_path, "r") as file:
            for line in file:
                if line.startswith("private_key"):
                    private_key = ast.literal_eval(line.split('=')[1].strip())
                if line.startswith("company"):
                    company = line.split('=')[1].strip()
                if line.startswith("server.public_key"):
                    server_public_key = ast.literal_eval(line.split('=')[1].strip())
        return private_key, company, server_public_key
    except FileNotFoundError:
        print(f"Error: {file_path} not found!")
        sys.exit(1)

# Authenticate the user
def authenticate_user(username, password, credentials):
    if username in credentials and credentials[username] == password:
        return True
    return False

def ssl_handshake(client_socket):
    # Send the client’s one-time key
    one_time_key_length = 128
    one_time_key = os.urandom(one_time_key_length)
    client_socket.send(one_time_key)

    # Receive the server’s one-time key
    server_one_time_key = client_socket.recv(1024)

    return server_one_time_key, one_time_key

def start_client():
    # Retrieve the command-line arguments
    username = sys.argv[1]  # Username
    port = int(sys.argv[2])  # Port number
    users_file = sys.argv[3]  # Path to users file

    # Load user credentials
    user_credentials, company, server_public_key = load_user_credentials(users_file)

    # Check if user exists
    if username not in user_credentials:
        print("Authentication failed: User not found.")
        sys.exit(1)

    password = input("Enter password: ")

    # Authenticate the user
    if not authenticate_user(username, password, user_credentials):
        print("Authentication failed: Incorrect password.")
        sys.exit(1)

    # Client connection setup
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", port))
    print("Connected to server.")

    # Perform SSL handshake and exchange keys
    server_key, client_key = ssl_handshake(client)
    print(f"Server's One-Time Key received: {server_key}")

    # Read message from the keyboard
    message = input("Enter message to send to server: ")

    # Encrypt the message with the one-time key and send it
    encrypted_message = encode_packet(message.encode(), client_key)
    client.send(encrypted_message)
    print(f"Sent encrypted message: {encrypted_message}")

    # Receive the encrypted response from the server
    encrypted_response = client.recv(1024)
    print(f"Received encrypted response: {encrypted_response}")

    # Decrypt the response using the one-time key
    decrypted_response = decode_packet(encrypted_response, client_key)
    print(f"Decrypted response: {decrypted_response.decode()}")

    # Close the connection
    client.close()

if __name__ == "__main__":
    start_client()
