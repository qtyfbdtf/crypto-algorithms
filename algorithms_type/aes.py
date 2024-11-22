import os


def generate_128_bit_key() -> bytes:
    """Generates a 128-bit (16-byte) AES key."""
    return os.urandom(16)


def generate_iv() -> bytes:
    """Generates a 16-byte Initialization Vector (IV)."""
    return os.urandom(16)


def xor_bytes(block1: bytes, block2: bytes) -> bytes:
    """XOR two byte sequences."""
    return bytes([b1 ^ b2 for b1, b2 in zip(block1, block2)])


def message_to_blocks(message: bytes, block_size=16) -> list:
    """Splits the message into blocks of block_size bytes."""
    return [message[i:i + block_size] for i in range(0, len(message), block_size)]


def message_padding(message: str, block_size=16) -> bytes:
    """Pads the message to ensure it is a multiple of block_size using PKCS#7 padding."""
    message_bytes = message.encode()  # Ensure message is in bytes
    padding_len = block_size - (len(message_bytes) % block_size)
    return message_bytes + bytes([padding_len] * padding_len)


def galois_multiply(a, b) -> list:
    """Perform multiplication in GF(2^8) as used in AES."""
    p = 0
    for i in range(8):
        if b & 1:  # If the least significant bit of b is 1
            p ^= a
        carry = a & 0x80  # Check if the high bit of a is 1
        a <<= 1  # Shift a left
        if carry:
            a ^= 0x1b
        b >>= 1  # Shift b right
    return p & 0xff  # Ensure the result fits in one byte


def sub_bytes(state, s_box) -> list:
    """Apply SubBytes transformation on the state matrix."""
    return [[s_box[byte] for byte in row] for row in state]


def shift_rows(state) -> list:
    """Perform the ShiftRows transformation on the state matrix."""
    return [row[i:] + row[:i] for i, row in enumerate(state)]


def mix_columns(state) -> list:
    """Perform the MixColumns transformation on the state matrix."""
    for col in range(4):  # Process each column
        a = state[0][col]
        b = state[1][col]
        c = state[2][col]
        d = state[3][col]

        # Compute the transformed column
        state[0][col] = galois_multiply(a, 2) ^ galois_multiply(b, 3) ^ c ^ d
        state[1][col] = a ^ galois_multiply(b, 2) ^ galois_multiply(c, 3) ^ d
        state[2][col] = a ^ b ^ galois_multiply(c, 2) ^ galois_multiply(d, 3)
        state[3][col] = galois_multiply(a, 3) ^ b ^ c ^ galois_multiply(d, 2)

    return state


def add_round_key(state, round_key) -> list:
    """XOR the state matrix with the round key."""
    return [[state[row][col] ^ round_key[row][col] for col in range(4)] for row in range(4)]


def key_schedule(key, s_box) -> list:
    """Generate AES-128 round keys from the original 16-byte key."""
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    def sub_word(word):
        """Substitute each byte in the word using the AES S-Box."""
        return [s_box[b] for b in word]

    def rot_word(word):
        """Rotate the word (4 bytes) left by one position."""
        return word[1:] + word[:1]

    # Split the initial key into 4 words (4 bytes each)
    words = [list(key[i: i + 4]) for i in range(0, len(key), 4)]

    for i in range(4, 44):  # Generate 44 words total (AES-128)
        temp = words[i - 1]  # Get the previous word
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))  # Apply RotWord and SubWord
            temp[0] ^= RCON[(i // 4) - 1]  # Add Rcon to the first byte
        words.append([w ^ t for w, t in zip(words[i - 4], temp)])
    return words


def aes_round(state, round_key, s_box) -> list:
    """Perform one AES round: SubBytes, ShiftRows, MixColumns, AddRoundKey."""
    state = sub_bytes(state, s_box)     # Step 1: SubBytes
    state = shift_rows(state)          # Step 2: ShiftRows
    state = mix_columns(state)         # Step 3: MixColumns
    state = add_round_key(state, round_key)  # Step 4: AddRoundKey
    return state


def final_round(state, round_key, s_box) -> list:
    """Perform the final AES round: SubBytes, ShiftRows, AddRoundKey."""
    state = sub_bytes(state, s_box)     # Step 1: SubBytes
    state = shift_rows(state)          # Step 2: ShiftRows
    state = add_round_key(state, round_key)  # Step 3: AddRoundKey
    return state


def aes_encrypt(block, round_keys, s_box) -> list:
    """Perform AES encryption on a single 128-bit block."""
    state = [list(block[i:i + 4]) for i in range(0, len(block), 4)]  # Convert block to 4x4 matrix

    # Initial AddRoundKey
    state = add_round_key(state, round_keys[0:4])

    # Perform 9 main rounds
    for round in range(1, 10):
        state = aes_round(state, round_keys[round * 4:(round + 1) * 4], s_box)

    # Perform final round
    state = final_round(state, round_keys[10 * 4:(10 + 1) * 4], s_box)

    return state


def aes_encrypt_cbc(plaintext: bytes, key: bytes, s_box: list, iv: bytes) -> bytes:
    """Encrypt plaintext using AES in CBC mode."""
    round_keys = key  # Placeholder for key schedule
    blocks = message_to_blocks(plaintext)
    ciphertext = []
    previous_block = iv

    for block in blocks:
        block = xor_bytes(block, previous_block)
        encrypted_block = block
        ciphertext.append(encrypted_block)
        previous_block = encrypted_block

    return b''.join(ciphertext)


def aes_main(message: str):
    """Encrypt a message using AES in CBC mode."""
    try:
        key = generate_128_bit_key()
        iv = generate_iv()

        S_BOX = [  # AES substitution box for byte substitution
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

        padded_message = message_padding(message)
        encrypted_message = aes_encrypt_cbc(padded_message, key, S_BOX, iv)

        return {
            "encrypted_message": encrypted_message.hex(),
            "key": key.hex(),
            "iv": iv.hex()
        }

    except Exception as e:
        raise ValueError(f"AES encryption failed: {e}")