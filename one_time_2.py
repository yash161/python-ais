import sys
import random
import base64

def new_key(length):
    """Generate a new random key of the specified length."""
    return bytes([random.randint(0, 255) for _ in range(length)])

def xor(data, key):
    """XOR the data with the key, repeating the key if necessary."""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]  # Repeat key if shorter than data
    return bytes(result)

def encode(text, key):
    """Encode the text by XORing it with the key and then base64 encoding the result."""
    # XOR the text with the key
    xor_result = xor(text.encode(), key)
    
    # Encode the XOR result in base64 for safe printing
    return base64.b64encode(xor_result).decode('utf-8')

def decode(encoded_text, key):
    """Decode the base64-encoded text by first base64 decoding and then XORing with the key."""
    # Decode the base64 encoded text to bytes
    decoded_b64 = base64.b64decode(encoded_text.encode('utf-8'))
    
    # XOR the result to decode the original text
    return xor(decoded_b64, key).decode(errors='ignore')

def main():
    if len(sys.argv) < 3:
        print("Usage: python one_time_2.py <key> <text> [<text>...]")
        sys.exit(1)

    key = sys.argv[1].encode()  # Convert key to bytes

    for i in range(2, len(sys.argv)):
        original_text = sys.argv[i]
        print(f"The Original text is {original_text}")

        # Encode the text
        encoded = encode(original_text, key)
        print(f"Encoded into {encoded}")

        # Decode the text
        decoded = decode(encoded, key)
        print(f"Decoded into {decoded}")

if __name__ == "__main__":
    main()
