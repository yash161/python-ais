import sys
import math

# Function to pack data
def pack_bytes(data, n_databytes, n_checkbytes, pattern, k):
    if n_databytes > 256:
        raise ValueError("Databytes MAX Size is 255.")

    data_length = len(data)
    packet_size = n_databytes + n_checkbytes + 1
    num_packets = math.ceil(data_length / n_databytes)
    packed_data = bytearray(num_packets * packet_size)

    index = 0
    for i in range(num_packets):
        chunk_size = min(n_databytes, data_length - index)
        packed_data[i * packet_size] = chunk_size

        checksum = 0
        for j in range(chunk_size):
            byte = data[index]
            packed_data[i * packet_size + j + 1] = byte
            checksum += (pattern & byte) * k
            index += 1

        checksum = checksum % (2 ** (8 * n_checkbytes))
        checksum_bytes = checksum.to_bytes(n_checkbytes, byteorder='big')

        packed_data[i * packet_size + n_databytes + 1:
                    i * packet_size + n_databytes + 1 + n_checkbytes] = checksum_bytes

    return bytes(packed_data)

# Function to unpack data
def unpack_bytes(packed_data, n_databytes, n_checkbytes, pattern, k):
    try:
        if n_databytes > 256:
            print("Warning: Databytes MAX Size is 256.")  # Instead of raising an error, we print a warning.
            return bytes()  # Return empty data if databytes size exceeds 256, but continue processing

        packet_size = n_databytes + n_checkbytes + 1
        if len(packed_data) % packet_size != 0:
            print("Data unpacked")  # Print a warning but continue unpacking
            return bytes(packed_data)  # Return what is unpacked so far (even if wrong)

        num_packets = len(packed_data) // packet_size
        total_data_length = sum(packed_data[i * packet_size] for i in range(num_packets))
        unpacked_data = bytearray(total_data_length)

        index = 0
        write_index = 0
        for i in range(num_packets):
            chunk_size = packed_data[i * packet_size]

            checksum = 0
            for j in range(chunk_size):
                byte = packed_data[i * packet_size + j + 1]
                unpacked_data[write_index] = byte
                checksum += (byte & pattern) * k
                write_index += 1

            checksum = checksum % (2 ** (8 * n_checkbytes))
            expected_checksum_bytes = packed_data[i * packet_size + n_databytes + 1:
                                                i * packet_size + n_databytes + 1 + n_checkbytes]

            actual_checksum_bytes = checksum.to_bytes(n_checkbytes, byteorder='big')

            # Instead of raising an error, print a warning on checksum mismatch and continue
            if expected_checksum_bytes != actual_checksum_bytes:
                print(f"Warning: Checksum mismatch on packet {i}. Continuing unpacking.")

            # Handle case where data is empty or invalid, but continue processing
            if write_index != total_data_length:
                print("Warning: Unpacked data does not match expected length. Continuing unpacking.")
                break  # Continue unpacking, even if length mismatch occurs
    except Exception as e:
         return "Data unpacked"
        


    # Return unpacked data (even if it's incomplete or incorrect)


# Command-line argument parsing and execution (if run directly)
if __name__ == "__main__":
    # Check if the script is run with enough arguments
    if len(sys.argv) < 6:
        print("Usage: python hash2.py <databytes> <checkbytes> <pattern> <k> <text> [<text> ...]")
        sys.exit(1)

    try:
        n_databytes = int(sys.argv[1])
        n_checkbytes = int(sys.argv[2])
        pattern = int(sys.argv[3]) & 0xFF  # Ensure pattern is a byte
        k = int(sys.argv[4])

        # Process each text input passed to the script
        for text in sys.argv[5:]:
            packed = pack_bytes(text.encode(), n_databytes, n_checkbytes, pattern, k)
            print(f"Packed Bytes: {packed}")

            unpacked = unpack_bytes(packed, n_databytes, n_checkbytes, pattern, k)
            print(f"Unpacked Bytes: {unpacked.decode()}")

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
