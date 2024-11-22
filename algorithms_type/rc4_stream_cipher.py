def initialize_state_array(key: str) -> list:
    """Initialize the state array and perform key scheduling for RC4."""
    s = [i for i in range(256)]
    key_list = [ord(char) for char in key]
    t = key_list * (len(s) // len(key_list)) + key_list[:len(s) % len(key_list)]

    j = 0
    for i in range(256):
        j = (j + s[i] + t[i]) % 256
        s[i], s[j] = s[j], s[i]
    return s

def generate_keystream(length: int, s: list) -> list:
    """Generate a keystream of the specified length for RC4."""
    i = j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) % 256
        keystream.append(s[t])
    return keystream

def encrypt_message_with_keystream(message: str, keystream: list) -> list:
    """Encrypt the message using XOR with the keystream."""
    ascii_values = [ord(char) for char in message]
    encrypted_message = [msg_byte ^ key_byte for msg_byte, key_byte in zip(ascii_values, keystream)]
    return encrypted_message

def convert_to_hex(encrypted_message: list) -> str:
    """Convert the encrypted message to a hex string for display."""
    return ' '.join(format(val, '02x') for val in encrypted_message)

def rc4_encryption(message: str, key: str) -> str:
    """Main RC4 encryption function."""
    s = initialize_state_array(key)
    keystream = generate_keystream(len(message), s)
    encrypted_message = encrypt_message_with_keystream(message, keystream)
    return convert_to_hex(encrypted_message)


def rc4_main(message: str, key: str) -> str:
    """Encrypt a message using RC4 Stream Cipher."""
    return rc4_encryption(message, key)

