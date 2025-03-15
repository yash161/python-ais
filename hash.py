import sys

def calculate_checksum(data_bytes, pattern, k, ncheckbytes):
    """Computes the checksum based on the given formula."""
    print(f"\nCalculating checksum for data bytes: {data_bytes}")
    
    # Display data bytes in binary format for visualization
    data_bits = [format(byte, '08b') for byte in data_bytes]
    print(f"Data bytes in binary: {data_bits}")
    
    # Compute the checksum by applying bitwise AND and multiplication
    checksum = 0
    for byte in data_bytes:
        checksum_part = byte & pattern
        print(f"Byte: {format(byte, '08b')} & Pattern: {format(pattern, '08b')} = {format(checksum_part, '08b')}")
        checksum += checksum_part
    
    print(f"Checksum after bitwise AND for each byte: {checksum}")
    
    checksum *= k
    print(f"Checksum after multiplication by k={k}: {checksum}")
    
    checksum = checksum % (2 ** (8 * ncheckbytes))  # Modulo 2^(8*ncheckbytes)
    print(f"Checksum after modulo operation (mod 2^{8 * ncheckbytes}): {checksum}")
    
    checksum_bytes = checksum.to_bytes(ncheckbytes, byteorder="big")  # Convert to bytes
    print(f"Checksum in bytes (to be appended to packet): {checksum_bytes}")
    return checksum_bytes

def pack_message(data_bytes, pattern, k, ncheckbytes):
    """Packs the message with a special control character and checksum."""
    print(f"\nPacking message with data bytes: {data_bytes}")
    
    # Calculate checksum
    checksum_bytes = calculate_checksum(data_bytes, pattern, k, ncheckbytes)
    
    # Add special control character (♣ = ASCII 5) at the start
    packed_bytes = bytes([5]) + bytes(data_bytes) + checksum_bytes  # 5 = ♣
    
    # Print the packed bytes and their binary representation
    packed_bits = [format(byte, '08b') for byte in packed_bytes]
    print(f"\nPacked bytes in binary: {packed_bits}")
    
    print(f"\nThe packet size is {len(packed_bytes)} bytes.")
    print(f"Even though the number of data bytes is {len(data_bytes)} in a packet, only {len(data_bytes)} will be used.")
    print(f"The first part of the packet (control character + data): {packed_bits[:len(data_bytes) + 1]}")
    
    return packed_bytes

def unpack_message(packed_bytes, ncheckbytes):
    """Extracts the original message from packed bytes."""
    print(f"\nUnpacking message from packed bytes: {packed_bytes}")
    unpacked_message = packed_bytes[1:-ncheckbytes].decode("utf-8")  # Exclude first byte (control character) and checksum
    print(f"Unpacked message: {unpacked_message}")
    return unpacked_message

def main():
    """Handles command-line arguments and processes the input."""
    if len(sys.argv) != 6:
        print("Usage: python Hash.py <ndatabytes> <ncheckbytes> <pattern> <k> <message>")
        sys.exit(1)

    # Parse input arguments
    ndatabytes = int(sys.argv[1])  # Number of data bytes
    ncheckbytes = int(sys.argv[2])  # Number of checksum bytes
    pattern = int(sys.argv[3])  # Bit pattern
    k = int(sys.argv[4])  # Multiplier
    message = sys.argv[5]  # Input message

    print(f"Input parameters: ndatabytes={ndatabytes}, ncheckbytes={ncheckbytes}, pattern={pattern}, k={k}, message={message}")

    # Convert message to byte values, limit to ndatabytes
    data_bytes = [ord(char) for char in message[:ndatabytes]]  
    print(f"Data bytes: {data_bytes}")

    # Pack the message
    packed_bytes = pack_message(data_bytes, pattern, k, ncheckbytes)

    # Unpack the message
    unpacked_message = unpack_message(packed_bytes, ncheckbytes)

    # Print results
    print("\nPacked Bytes:")
    print(packed_bytes.decode(errors="ignore"))  # Decode ignoring errors to show control chars
    print("Unpacked Bytes:")
    print(unpacked_message)

if __name__ == "__main__":
    main()
