def permute (bits, table):

    for place in table:
        if place < 1 or place > len(bits):
            raise ValueError("Table values must be between 1 and the length of bits")
        
    permuted_bits = ""

    for place in table:
        permuted_bits += bits[place - 1]
    return permuted_bits

def left_rotate(bits, shifts):
    """
    Performs a left rotation on a string of bits.

    Args:
        bits (str): The string of bits to be rotated.
        shifts (int): The number of positions to rotate the bits to the left.

    Returns:
        str: The left-rotated string of bits.
    """
    
    if shifts < 0:
        raise ValueError("Number of shifts must be non-negative.")

    if not bits:
        raise ValueError("Bit string cannot be empty.")
    
    shifts = shifts % len(bits)  # Handle cases where shifts > len(bits)
    return bits[shifts:] + bits[:shifts]

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

def split_into_blocks(bits, block_size):
    """
    Splits a binary string into blocks of equal size.

    Args:
        bits (str): Binary string.
        block_size (int): Size of each block.

    Returns:
        list[str]: List of blocks.
    """

    if block_size <= 0:
        raise ValueError("Block size must be positive.")

    if len(bits) % block_size != 0:
        raise ValueError("Binary string length must be divisible by block size.")

    return [
        bits[i:i + block_size]
        for i in range(0, len(bits), block_size)
    ]

def xor_bytes(bits1, bits2):
    """
    Performs XOR operation on two binary strings of equal length

    Args:
        bits1 (str): First binary string
        bits2 (str): Second binary string

    Returns:
        str: Result of the XOR operation
    """
    if len(bits1) != len(bits2):
        raise ValueError("Both binary strings must have the same length")

    if any(bit not in ("0", "1") for bit in bits1 + bits2):
        raise ValueError("Binary strings must contain only 0 and 1")

    return "".join(
        "1" if bit1 != bit2 else "0"
        for bit1, bit2 in zip(bits1, bits2)
    )