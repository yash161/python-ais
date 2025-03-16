from rsa import encrypt, decrypt
from rsa import encrypt, decrypt
from hash2 import unpack_bytes
from one_time import generate_one_time_key, encode_packet, decode_packet
from hash2 import pack_bytes
import re
def load_keys(filename):
    with open(filename, 'r') as file:
        content = file.read()
        match = re.search(r'\{(\d+),(\d+)\}', content)
        if match:
            d, n = match.groups()
            return {'d': int(d), 'n': int(n)}
    return None
def load_server_public_key(filename):
    with open(filename, 'r') as file:
        content = file.read()
        match = re.search(r'server\.public_key=\{(\d+),(\d+)\}', content)
        if match:
            e, n = match.groups()
            return {'e': int(e), 'n': int(n)}
    return None
server_public_key=load_server_public_key(r"C:\Users\yshah12\Desktop\ais_project_python\python-ais\users.txt")
print(server_public_key)
message="hello"
message_bytes = message.encode()
one_time_key = generate_one_time_key(len(message_bytes))
encoded_message = encode_packet(message_bytes, one_time_key)
packed_message = pack_bytes(message_bytes, 123, 31, 2, 31)

print("encoded",packed_message)
data = unpack_bytes(packed_message, 123, 31, 2, 31)
print("data",data)