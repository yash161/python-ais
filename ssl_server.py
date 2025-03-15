import socket
import os
import sys
import ast
from rsa import generate_rsa_keys, encrypt, decrypt, text_to_int, int_to_text
# generate_one_time_key, encode_packet, decode_packet

# Load user credentials and keys from file
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

# Load private key from file
def load_private_key(file_path):
    try:
        with open(file_path, "r") as file:
            private_key = file.read().strip()
        return private_key
    except FileNotFoundError:
        print(f"Error: {file_path} not found!")
        sys.exit(1)

def handle_client(client_socket, private_key, company, server_public_key):
    print(f"Server: Using Private Key: {private_key}")
    # Receive the client’s one-time key
    one_time_key_length = 128
    one_time_key = os.urandom(one_time_key_length)
    client_socket.send(one_time_key)

    # Receive the encrypted message from the client
    encrypted_message = client_socket.recv(1024)
    print(f"Received encrypted message: {encrypted_message}")

    # Decrypt the message using the one-time key
    decrypted_message = decode_packet(encrypted_message, one_time_key)
    print(f"Decrypted message: {decrypted_message.decode()}")

    # Modify the message: flip case
    modified_message = decrypted_message.decode().swapcase()

    # Re-encrypt the modified message using one-time key
    encrypted_response = encode_packet(modified_message.encode(), one_time_key)
    client_socket.send(encrypted_response)
    print(f"Encrypted response: {encrypted_response}")

    # Close the connection
    client_socket.close()

def start_server(private_key_file, users_file, port):
    # Load private key and user credentials
    private_key, company, server_public_key = load_user_credentials(users_file)

    # Set up the server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", port))
    server.listen(5)
    print(f"Server started and listening on port {port}.")

    while True:
        client_socket, addr = server.accept()
        print(f"Connection from {addr} has been established.")

        # Handle the client connection
        handle_client(client_socket, private_key, company, server_public_key)

if __name__ == "__main__":
    # Retrieve the command-line arguments
    private_key_file = sys.argv[1]  # Server private key file
    users_file = sys.argv[2]        # Users file
    port = int(sys.argv[3])         # Port number

    # Start the server with the given configurations
    start_server(private_key_file, users_file, port)
