import socket
import re
import sys
import argparse
# from rsa2 import encrypt,decrypt
from rsa import encrypt, decrypt
from hash import calculate_checksum, pack_message, unpack_message
from one_time import generate_one_time_key, encode_packet, decode_packet
from hash2 import pack_bytes

def load_keys(filename):
    with open(filename, 'r') as file:
        content = file.read()
        match = re.search(r'\{(\d+),(\d+)\}', content)
        print("match",match)
        # if match:
        #     d, n = match.groups()
        #     return {'d': int(d), 'n': int(n)}
    return None
def load_users(filename):
    with open(filename, 'r') as file:
        content = file.read()
        match = re.search(r'company=([^\n]+)', content)  # Capture everything after 'company='
        if match:
            company_name = match.group(1)  # Extract the matched company name
            print("MATCH:", match)  # Debug print
            print("Extracted Company Name:", company_name)  # Print extracted value
            return {"company":company_name}
    return {}


def load_server_public_key(filename):
    with open(filename, 'r') as file:
        content = file.read()
        match = re.search(r'server\.public_key=\{(\d+),(\d+)\}', content)
        if match:
            e, n = match.groups()
            return {'e': int(e), 'n': int(n)}
    return None

def main():
    print("args", sys.argv)

    # Update argument parsing to handle both named and positional arguments
    parser = argparse.ArgumentParser(description="SSL client example")
    parser.add_argument('--server_users', type=str, required=True, help="Path to the users file")
    parser.add_argument('--server_port', type=int, required=True, help="Port for the server")
    parser.add_argument('server_address', type=str, help="Server address (e.g., localhost)")
    parser.add_argument('username', type=str, help="Username to authenticate with")


    args = parser.parse_args()

    users_file = args.server_users
    port = args.server_port
    server_address = args.server_address
    username = args.username

    users = load_users(users_file)
    server_public_key = load_server_public_key(users_file)

    print(f"Users: {users} and Server Public Key: {server_public_key}")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address_tuple = (server_address, port)
    client_socket.connect(server_address_tuple)

    try:
        print(f"users:{users}")
        # For handshake, you'd normally have some authentication of users
        company = next(iter(users.values()), None)
        print(company)
        if company is None:
            print("User not found in the users file.")
            client_socket.close()
            exit()
        one_time_key = generate_one_time_key(len(username))
        encrypted_username = encrypt(username, (server_public_key["e"], server_public_key["n"]))
        encrypted_company = encrypt(company,(server_public_key["e"], server_public_key["n"]))
        encrypted_key = encrypt(one_time_key, (server_public_key["e"], server_public_key["n"]))
        
        print(f"Sending Data : {encrypted_username} compan:{encrypted_company} and key:{encrypted_key}")
        handshake_data = b'||'.join([encrypted_username.to_bytes((encrypted_username.bit_length() + 7) // 8, 'big'),
                                     encrypted_company.to_bytes((encrypted_company.bit_length() + 7) // 8, 'big'),
                                     encrypted_key.to_bytes((encrypted_key.bit_length() + 7) // 8, 'big')])

        client_socket.sendall(handshake_data)
        ack = client_socket.recv(1024)
        if ack != b'ACK':
            print("Handshake failed!")
            client_socket.close()
            exit()

        # Proceed with message exchange
        # message = input("Enter the message to send: ")
        message=[{
            "",""
        },{

        }]
        message_bytes = message.encode()

        # Generate a one-time key for the message
        one_time_key = generate_one_time_key(len(message_bytes))
        encoded_message = encode_packet(message_bytes, one_time_key)
        print("encoded message::",encoded_message)
        packed_message = pack_bytes(message_bytes, 123, 31, 2, 31)

        client_socket.sendall(packed_message)

        # Receive the modified encrypted data
        encrypted_modified_data = client_socket.recv(1024)
        modified_data = (int.from_bytes(encrypted_modified_data, 'big'), (server_public_key["e"], server_public_key["n"]))

        # Decode the modified data using the one-time key
        decoded_modified_data = decode_packet(modified_data, one_time_key).decode()

    finally:
        client_socket.close()
    
if __name__ == "__main__":
    main()
