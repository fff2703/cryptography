from permutations import E, P, IP, FP
from utils import permute, xor_bytes, split_block
from sboxes import substitute
from key_schedule import generate_round_keys

def expand(right_half):
    """
    Expands a 32-bit half-block to 48 bits using the expansion permutation

    Args:
        right_half (str): The right half of the block (32 bits)

    Returns:
        str: The expanded block (48 bits)
    """
    if len(right_half) != 32:
        raise ValueError("Right half length must be 32 bits to expand.")

    return permute(right_half, E)

def feistel(right_half, round_key):
    """
    Applies the Feistel function to the right half of the block using the given round key

    Args:
        right_half (str): The right half of the block (32 bits)
        round_key (str): The round key for this round (48 bits)

    Returns:
        str: The result of the Feistel function (32 bits)
    """
    if len(right_half) != 32:
        raise ValueError("Right half length must be 32 bits for Feistel function")
    if len(round_key) != 48:
        raise ValueError("Round key length must be 48 bits for Feistel function")

    # Step 1: Expand the right half from 32 to 48 bits
    expanded_half = expand(right_half)

    # Step 2: XOR with the round key
    xor_result = xor_bytes(expanded_half, round_key)

    # Step 3: Apply S-box substitution
    substituted = substitute(xor_result)

    # Step 4: Apply permutation P
    permuted_result = permute(substituted, P)

    return permuted_result

def des_round(left_half, right_half, round_key):
    """
    Performs one round of the DES algorithm

    Args:
        left_half (str): The left half of the block (32 bits)
        right_half (str): The right half of the block (32 bits)
        round_key (str): The round key for this round (48 bits)

    Returns:
        tuple: A tuple containing the new left and right halves after the round
    """
    if len(left_half) != 32 or len(right_half) != 32:
        raise ValueError("Both halves must be 32 bits long for DES round")
    if len(round_key) != 48:
        raise ValueError("Round key length must be 48 bits for DES round")

    # Apply the Feistel function to the right half
    feistel_result = feistel(right_half, round_key)

    # XOR the result with the left half
    new_right_half = xor_bytes(left_half, feistel_result)

    # The new left half is simply the old right half
    new_left_half = right_half

    return new_left_half, new_right_half

def des_rounds(left_half, right_half, round_keys):
    """
    Performs all 16 rounds of the DES algorithm

    Args:
        left_half (str): The left half of the block (32 bits)
        right_half (str): The right half of the block (32 bits)
        round_keys (list): A list of 16 round keys, each 48 bits long

    Returns:
        tuple: A tuple containing the final left and right halves after all rounds
    """
    if len(left_half) != 32 or len(right_half) != 32:
        raise ValueError("Both halves must be 32 bits long for DES rounds")
    if len(round_keys) != 16:
        raise ValueError("There must be exactly 16 round keys for DES")
    if any(len(key) != 48 for key in round_keys):
        raise ValueError("Each round key must be 48 bits long")

    for round_key in round_keys:
        left_half, right_half = des_round(left_half, right_half, round_key) # Update both halves with the result of one DES round (multiple assignment)
    return left_half, right_half

def encrypt_block(block, round_keys):
    """
    Encrypts a single 64-bit block using DES.

    Args:
        block (str): A 64-bit binary string.
        round_keys (list): A list of 16 round keys.

    Returns:
        str: The encrypted 64-bit block.
    """
    if len(block) != 64:
        raise ValueError("Block length must be 64 bits for DES encryption")
    if len(round_keys) != 16:
        raise ValueError("There must be exactly 16 round keys for DES encryption")
    if any(len(key) != 48 for key in round_keys):
        raise ValueError("Each round key must be 48 bits long")

    # Step 1: Initial Permutation
    permuted_block = permute(block, IP)

    # Step 2: Split the block into left and right halves
    left_half, right_half = split_block(permuted_block)

    # Step 3: Perform the 16 rounds of DES
    left_half, right_half = des_rounds(left_half, right_half, round_keys)

    # Step 4: Combine the halves in reverse order (right half first)
    combined_block = right_half + left_half

    # Step 5: Final Permutation
    encrypted_block = permute(combined_block, FP)

    return encrypted_block

def decrypt_block(block, round_keys):
    """
    Decrypts a single 64-bit block using DES

    Args:
        block (str): A 64-bit binary string
        round_keys (list): A list of 16 round keys
    Returns:
        str: The decrypted 64-bit block
    """
    if len(block) != 64:
        raise ValueError("Block length must be 64 bits for DES decryption")
    if len(round_keys) != 16:
        raise ValueError("There must be exactly 16 round keys for DES decryption")

    # Step 1: Initial Permutation
    permuted_block = permute(block, IP)

    # Step 2: Split the block into left and right halves
    left_half, right_half = split_block(permuted_block)

    # Step 3: Perform the 16 rounds of DES in reverse order
    left_half, right_half = des_rounds(
    left_half,
    right_half,
    round_keys[::-1]
)

    # Step 4: Combine the halves in reverse order (right half first)
    combined_block = right_half + left_half

    # Step 5: Final Permutation
    decrypted_block = permute(combined_block, FP)

    return decrypted_block

def text_to_binary(text):
    """
    Converts a string of text to its binary representation

    Args:
        text (str): The input string

    Returns:
        str: A binary string representing the input text
    """
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary):
    """
    Converts a binary string back to its text representation

    Args:
        binary (str): The input binary string

    Returns:
        str: The text representation of the binary string
    """
    if len(binary) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8 to convert to text")

    return ''.join(chr(int(binary[i:i + 8], 2)) for i in range(0, len(binary), 8))

def add_padding(binary):
    """
    Adds PKCS#7-style padding to a binary string.

    Args:
        binary (str): The input binary string.

    Returns:
        str: The padded binary string.
    """
    if len(binary) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8")

    block_size = 64  # bits

    padding_bits = block_size - (len(binary) % block_size)

    if padding_bits == 0:
        padding_bits = block_size

    padding_bytes = padding_bits // 8

    padding = format(padding_bytes, "08b") * padding_bytes

    return binary + padding

def remove_padding(binary):
    """
    Removes PKCS#7-style padding from a binary string.

    Args:
        binary (str): The padded binary string.

    Returns:
        str: The original binary string.
    """
    if len(binary) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8")

    last_byte = binary[-8:]
    padding_length = int(last_byte, 2)

    if padding_length < 1 or padding_length > 8:
        raise ValueError("Invalid padding")

    expected_padding = format(padding_length, "08b") * padding_length

    if binary[-padding_length * 8:] != expected_padding:
        raise ValueError("Invalid padding")

    return binary[:-padding_length * 8]


def encrypt(plaintext, key):
        """
        Encrypts a plaintext string using DES with the provided key

        Args:
            plaintext (str): The input plaintext string
            key (str): A 64-bit binary string representing the DES key

        Returns:
            str: The encrypted ciphertext as a binary string
        """
        if len(key) != 64:
            raise ValueError("Key length must be 64 bits for DES encryption")

        if any(bit not in ("0", "1") for bit in key):
            raise ValueError("Key must be a binary string containing only 0s and 1s")

        binary_plaintext = text_to_binary(plaintext)
        padded_binary = add_padding(binary_plaintext)

        round_keys = generate_round_keys(key)

        encrypted_blocks = []

        for i in range(0, len(padded_binary), 64):
            block = padded_binary[i:i + 64]
            encrypted_blocks.append(
                encrypt_block(block, round_keys)
            )

        return ''.join(encrypted_blocks)

def decrypt(ciphertext, key):
        """
        Decrypts a ciphertext string using DES with the provided key.

        Args:
            ciphertext (str): The input ciphertext as a binary string.
            key (str): A 64-bit binary string representing the DES key.

        Returns:
            str: The decrypted plaintext.
        """
        if len(key) != 64:
            raise ValueError("Key length must be 64 bits for DES decryption")

        if any(bit not in ("0", "1") for bit in key):
            raise ValueError("Key must be a binary string containing only 0s and 1s")

        if len(ciphertext) % 64 != 0:
            raise ValueError("Ciphertext length must be a multiple of 64 bits")

        if any(bit not in ("0", "1") for bit in ciphertext):
            raise ValueError("Ciphertext must be a binary string containing only 0s and 1s")

        # Generate round keys
        round_keys = generate_round_keys(key)

        # Decrypt each 64-bit block
        decrypted_blocks = []

        for i in range(0, len(ciphertext), 64):
            block = ciphertext[i:i + 64]
            decrypted_blocks.append(
                decrypt_block(block, round_keys)
            )

        plaintext_binary = ''.join(decrypted_blocks)

        # Remove padding
        unpadded_binary = remove_padding(plaintext_binary)

        # Convert binary to text
        return binary_to_text(unpadded_binary)
