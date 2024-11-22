def match_key_length(message: str, key: str) -> str:
    """Extend the key to match the length of the message."""
    return key * (len(message) // len(key)) + key[:len(message) % len(key)]

def encrypt_character(char: str, key_char: str, CHAR_RANGE: int = 26) -> str:
    """Encrypt a single character using the Vigenere cipher."""
    if char.islower():
        base = ord('a')
    else:
        base = ord('A')
    added_values = ord(char) + ord(key_char) - 2 * base
    final_char_code = added_values % CHAR_RANGE + base
    return chr(final_char_code)


def vigenere_encryption(message: str, key: str, include_special_chars: bool) -> str:
    """Encrypt a message using the Vigenere cipher with optional inclusion of special characters."""
    CHAR_RANGE = 26
    result = ''

    # Match the key length to the message length
    new_key = match_key_length(message, key)

    for i in range(len(message)):
        if message[i].isalpha():
            result += encrypt_character(message[i], new_key[i], CHAR_RANGE)
        else:
            if include_special_chars:
                result += message[i]

    return result

def vigenere_main(message: str, key: str, include_special_chars: bool) -> str:
    """Encrypt a message using the Vigenère cipher."""
    return vigenere_encryption(message, key, include_special_chars)

