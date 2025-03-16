import argparse
import random
from typing import Tuple
from math import gcd
from functools import reduce

# Function to generate a large prime number (simplified version for demonstration)
def generate_prime(bits: int) -> int:
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

# Simple primality test
def is_prime(n: int) -> bool:
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

# Function to compute modular inverse
def mod_inverse(a: int, m: int) -> int:
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

# Function to generate RSA keys
def generate_keys(bits: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    # Generate two distinct prime numbers p and q
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)

    # Compute n = p * q
    n = p * q

    # Compute Euler's totient function φ(n) = (p-1)*(q-1)
    phi_n = (p - 1) * (q - 1)

    # Choose a public key exponent e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = 65537  # Commonly used value for e
    while gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)

    # Compute the private key d such that (d * e) % φ(n) = 1
    d = mod_inverse(e, phi_n)

    # Return the public and private keys
    return (e, n), (d, n)

# Function to encrypt a message
def encrypt(message: str, public_key: Tuple[int, int]) -> str:
    e, n = public_key
    message_bytes = message.encode()
    cipher_bytes = [pow(b, e, n) for b in message_bytes]
    return ' '.join(map(str, cipher_bytes))

# Function to decrypt a message
def decrypt(cipher_text: str, private_key: Tuple[int, int]) -> str:
    d, n = private_key
    cipher_bytes = map(int, cipher_text.split())
    message_bytes = [pow(c, d, n) for c in cipher_bytes]
    return bytes(message_bytes).decode()

# Main function to parse command-line arguments and execute
def main():
    parser = argparse.ArgumentParser(description="RSA encryption/decryption")
    parser.add_argument("-help", action="store_true", help="Display help message")
    parser.add_argument("-gen", type=str, help="Generate keys and encrypt the message")
    parser.add_argument("-Dprime_size", type=int, default=8, help="Define the size of the prime numbers (default: 8 bits)")
    
    args = parser.parse_args()

    if args.help:
        print("RSA encryption tool\n")
        print("Usage:")
        print("  -help               Display this help message.")
        print("  -gen <message>      Generate keys and encrypt the provided message.")
        print("  -Dprime_size=<size> Specify the size of the prime numbers in bits (default: 8)")
        return

    if args.gen:
        bits = args.Dprime_size
        public_key, private_key = generate_keys(bits)

        print(f"\nGenerating RSA keys with {bits}-bit primes:")
        print(f"Public Key: {public_key}")
        print(f"Private Key: {private_key}")

        message = args.gen
        print(f"\nOriginal Message: {message}")

        cipher_text = encrypt(message, public_key)
        print(f"Encrypted Message: {cipher_text}")

        decrypted_message = decrypt(cipher_text, private_key)
        print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
