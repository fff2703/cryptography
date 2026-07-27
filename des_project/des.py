from permutations import permute, E, P, IP, FP
from sboxes import substitute
from utils import xor_bytes, split_block

def split_block(block):
    """
    Splits a block of bytes into two halves.

    Args:
        block (str): The block of bytes to be split

    Returns:
        tuple: A tuple containing the left and right halves of the block
    """
    if len(block) != 64:
        raise ValueError("Block length must be 64 bits to split into two 32-bit halves")

    mid = 32  # Calculated the midpoint of the block
    left_half = block[:mid]
    right_half = block[mid:]
    return left_half, right_half


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
        left_half, right_half = des_round(left_half, right_half, round_key) ## Update both halves with the result of one DES round (multiply assignment)
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