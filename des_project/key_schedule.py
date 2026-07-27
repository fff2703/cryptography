from utils import permute, left_rotate
from permutations import PC1, PC2

def permuted_choice_1(key):
    """
    Applies the PC-1 permutation to a 64-bit DES key.

    Args:
        key (str): A 64-bit binary string.

    Returns:
        str: A 56-bit binary string after the PC-1 permutation.
    """
    if len(key) != 64:
        raise ValueError("Key length must be 64 bits for PC-1 permutation.")

    return permute(key, PC1)


def generate_round_key(key):
    key56 = permuted_choice_1(key)

    c = key56[:28]
    d = key56[28:]

    c = left_rotate(c, 1)
    d = left_rotate(d, 1)

    combined_key = c + d

    round_key = permute(combined_key, PC2)

    return round_key