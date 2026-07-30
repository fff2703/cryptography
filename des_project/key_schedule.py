from utils import permute, left_rotate
from permutations import PC1, PC2, SHIFT_SCHEDULE

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


def generate_round_keys(key):
    """
    Generates all 16 DES round keys

    Args:
        key (str): A 64-bit binary DES key.

    Returns:
        list[str]: A list containing 16 round keys, each 48 bits long
    """
    round_keys = []
    key56 = permuted_choice_1(key)

    c = key56[:28]
    d = key56[28:]

    for shift in SHIFT_SCHEDULE:
        c = left_rotate(c, shift)
        d = left_rotate(d, shift)

        round_key = permute(c + d, PC2)
        round_keys.append(round_key)

    return round_keys