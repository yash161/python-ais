import random

# Compute greatest common divisor (GCD)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Extended Euclidean Algorithm to find modular inverse
def mod_inverse(e, phi):
    old_r, r = e, phi
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    if old_s < 0:
        old_s += phi  # Ensure positive value
    return old_s

# Miller-Rabin Primality Test for efficient prime checking
def is_prime(n, k=10):
    if n <= 1 or (n > 2 and n % 2 == 0):
        return False
    if n == 2:
        return True

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Generate a large prime number of size 'bits'
def generate_large_prime(bits=128):
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Ensure it's odd and of 'bits' length
        if is_prime(num):
            return num

# RSA Key Generation
def generate_rsa_keys():
    p = generate_large_prime()
    q = generate_large_prime()

    while q == p:
        q = generate_large_prime()

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = random.randrange(2, phi_n)
    while gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)

    d = mod_inverse(e, phi_n)

    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key

# Convert a string to an integer
def text_to_int(text):
    return int.from_bytes(text.encode('utf-8'), 'big')

# Convert an integer back to a string
def int_to_text(number):
    return number.to_bytes((number.bit_length() + 7) // 8, 'big').decode('utf-8')

# RSA Encryption
def encrypt(message, public_key):
    e, n = public_key
    message_int = text_to_int(message)
    cipher = pow(message_int, e, n)
    return cipher

# RSA Decryption
def decrypt(cipher, private_key):
    d, n = private_key
    message_int = pow(cipher, d, n)
    return int_to_text(message_int)

# Test RSA implementation
public_key, private_key = generate_rsa_keys()
print("Public Key:", public_key)
print("Private Key:", private_key)

message = "hello yash here"
print("Original Message:", message)

cipher_text = encrypt(message, public_key)
print("Encrypted:", cipher_text)

decrypted_message = decrypt(cipher_text, private_key)
print("Decrypted:", decrypted_message)
