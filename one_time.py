import os
import sys

def generate_one_time_key(packet_length):
    """Generates a random one-time key with the same length as the packet."""
    one_time_key = os.urandom(packet_length)  # Generates random bytes of length packet_length
    return one_time_key

def encode_packet(packet_bytes, one_time_key):
    """Encodes the packet using XOR with the one-time key."""
    encoded_packet = bytes([packet_byte ^ key_byte for packet_byte, key_byte in zip(packet_bytes, one_time_key)])
    return encoded_packet

def decode_packet(encoded_packet, one_time_key):
    """Decodes the packet using XOR with the same one-time key."""
    decoded_packet = bytes([encoded_byte ^ key_byte for encoded_byte, key_byte in zip(encoded_packet, one_time_key)])
    return decoded_packet

def main():
    """Handles command-line arguments and processes the input."""
    if len(sys.argv) != 3:
        print("Usage: python OneTimeHash.py <message>")
        sys.exit(1)

    message = sys.argv[2]  # Input message

    print(f"Original text is: {message}")

    # Convert message to byte values
    message_bytes = [ord(char) for char in message]

    # Generate the one-time key of the same length as the message
    one_time_key = generate_one_time_key(len(message_bytes))

    # Encode the message using XOR with the one-time key
    encoded_message = encode_packet(message_bytes, one_time_key)

    # Decode the message by applying XOR with the same one-time key
    decoded_message = decode_packet(encoded_message, one_time_key)

    # Convert the decoded message back to a string
    decoded_message_str = ''.join([chr(byte) for byte in decoded_message])

    # Print results in the requested format
    print(f"Encoded to: {''.join([chr(byte) for byte in encoded_message])}")
    print(f"Decoded to: {decoded_message_str}")

if __name__ == "__main__":
    main()
