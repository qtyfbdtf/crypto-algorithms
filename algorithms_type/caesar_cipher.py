def shift_character(char: str, shift: int, char_range: int = 26) -> str:
    """Shift a single alphabetic character by a specified amount."""
    if char.islower():
        first_char_code = ord('a')
        last_char_code = ord('z')
    else:
        first_char_code = ord('A')
        last_char_code = ord('Z')

    new_char_code = ord(char) - shift

    # Handle character wrap-around within the alphabet range
    if new_char_code > last_char_code:
        new_char_code -= char_range
    elif new_char_code < first_char_code:
        new_char_code += char_range

    return chr(new_char_code)

def encrypt_message(message: str, shift: int, include_special_chars: bool) -> str:
    """Encrypt a message using a Caesar Cipher shift, with optional inclusion of special characters."""
    result = ''
    for char in message:
        if char.isalpha():
            result += shift_character(char, shift)
        else:
            if include_special_chars:
                result += char
    return result

# Main function
def caesar_main(message: str, shift: int, include_special_chars: bool) -> str:
    """Encrypt a message using the provided parameters."""
    return encrypt_message(message, shift, include_special_chars)
