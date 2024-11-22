import base64
from sympy import isprime, randprime

def generate_large_prime(bits=512):
    """Generate a random prime number of approximately 'bits' bits."""
    lower_bound = 2**(bits - 1)
    upper_bound = 2**bits - 1
    return randprime(lower_bound, upper_bound)

prime = generate_large_prime()
# print("Generated Prime:", prime)


def is_coprime(a: int, b: int) -> bool:
    """Check if two numbers are coprime."""
    while b:
        a, b = b, a % b
    return a == 1

def mod_inverse(e: int, phi: int) -> int:
    """Compute the modular multiplicative inverse of e modulo phi."""
    original_phi = phi
    x0, x1 = 0, 1
    while e > 1:
        q = e // phi
        e, phi = phi, e % phi
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += original_phi
    return x1

def generate_keys() -> tuple:
    """Generate RSA public and private keys."""
    p = generate_large_prime()  # Generate first prime
    q = generate_large_prime()  # Generate second prime
    n = p * q
    phi = (p - 1) * (q - 1)
    e = next((i for i in range(2, phi) if is_coprime(phi, i)), None)
    if e is None:
        raise ValueError("No suitable public exponent found.")

    d = mod_inverse(e, phi)
    return (e, n), (d, n)  # Return public and private keys

def encrypt_message(message: str, public_key: tuple) -> list:
    """Encrypt message using the RSA public key."""
    e, n = public_key
    ascii_values = [ord(char) for char in message]
    encrypted_values = [pow(val, e, n) for val in ascii_values]
    return encrypted_values

def encode_to_base64(encrypted_values: list) -> str:
    """Convert the entire list of encrypted integers to a single Base64 string."""
    byte_data = b''.join(val.to_bytes((val.bit_length() + 7) // 8, 'big') for val in encrypted_values)
    base64_encoded = base64.b64encode(byte_data).decode('utf-8')
    return base64_encoded


def rsa_encryption(message: str) -> tuple:
    """Encrypt a message using RSA."""
    public_key, private_key = generate_keys()
    encrypted_message = encrypt_message(message, public_key)
    byte_lengths = [(val.bit_length() + 7) // 8 for val in encrypted_message]
    base64_encoded = encode_to_base64(encrypted_message)
    return base64_encoded, byte_lengths, private_key


def rsa_main(message: str) -> dict:
    """Encrypt a message using RSA and return encrypted message along with keys."""
    public_key, private_key = generate_keys()  # Generate keys
    encrypted_message, byte_lengths, _ = rsa_encryption(message)
    return {
        "encrypted_message": encrypted_message,
        "public_key": public_key,
        "private_key": private_key,
        "byte_lengths": byte_lengths
    }
