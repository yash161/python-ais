import socket
import re
import sys
from rsa import decrypt, encrypt
from hash import calculate_checksum, pack_message, unpack_message
from one_time import generate_one_time_key, encode_packet, decode_packet

def load_keys(filename):
    with open(filename, 'r') as file:
        content = file.read()
        match = re.search(r'\{(\d+),(\d+)\}', content)
        if match:
            d, n = match.groups()
            return {'d': int(d), 'n': int(n)}
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
    # if len(sys.argv) != 5:
    #     print("Usage: python server.py -Dserver.private_key=<file> -Dserver.users=<file> -Dserver.port=<port>")
    #     sys.exit(1)

    private_key_file = None
    users_file = None
    port = None
    print("args received::",sys.argv)
    for arg in sys.argv[1:]:
        if arg.startswith("--server.private_key="):
            private_key_file = arg.split("=")[1]
        elif arg.startswith("--server.users="):
            users_file = arg.split("=")[1]
        elif arg.startswith("--server.port="):
            port = int(arg.split("=")[1])

    if not private_key_file or not users_file or not port:
        print("Missing required arguments.")
        sys.exit(1)

    if not private_key_file or not users_file or not port:
        print("Missing required arguments.")
        sys.exit(1)

    server_private_key = load_keys(private_key_file)
    users = load_users(users_file)
    server_public_key = load_server_public_key(users_file)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', port)
    server_socket.bind(server_address)
    server_socket.listen(1)
    print(f"Server is listening on port {port}...")

    while True:
        connection, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        try:
            handshake_data = connection.recv(1024)
            encrypted_username, encrypted_company, encrypted_key = handshake_data.split(b'||')
            d = int(server_private_key['d'])  # Assuming server_private_key is a dictionary with 'd' as a string
            n = int(server_private_key['n'])  # Assuming server_private_key is a dictionary with 'n' as a string
            print(f"{d} and {n}")

            username = decrypt(int.from_bytes(encrypted_username, 'big'), (server_private_key["d"], server_public_key["n"]))
            company = decrypt(int.from_bytes(encrypted_company, 'big'), (server_private_key["d"], server_public_key["n"]))
            print(f"username {username} and company :{company}")
            print("company",company,users.get(company))
            print("users",users)
  
            if next(iter(users.values()), None) != company:
                print("Unauthorized client!")
                connection.close()
                continue

            one_time_key = decrypt(int.from_bytes(encrypted_key, 'big'), (server_private_key["d"], server_public_key["n"]))
            print(f"Received one-time key: {one_time_key}")

            connection.sendall(b'ACK')

            # Receive encrypted data
            encrypted_data = connection.recv(1024)
            decrypted_data = decrypt(int.from_bytes(encrypted_data, 'big'), (server_private_key["d"], server_public_key["n"]))
            print("DECR",decrypted_data)
            # Unpack the message to get the original data and checksum
            data, checksum = unpack_message(decrypted_data, 2)

            # Verify the checksum
            calculated_checksum = calculate_checksum(data, 123, 31, 2)
            if checksum != calculated_checksum:
                print("Data integrity check failed!")
                connection.close()
                continue

            # Modify the data (convert case)
            modified_data = data.swapcase()

            # Generate a new one-time key for the modified data
            new_one_time_key = generate_one_time_key(len(modified_data))
            encoded_modified_data = encode_packet(modified_data.encode(), new_one_time_key)

            # Encrypt the encoded modified data
            encrypted_modified_data = encrypt(encoded_modified_data, (server_private_key["d"], server_public_key["n"]))
            connection.sendall(encrypted_modified_data.to_bytes((encrypted_modified_data.bit_length() + 7) // 8, 'big'))

        finally:
            connection.close()

if __name__ == "__main__":
    main()