def permute (bits, table):

    for place in table:
        if place < 1 or place > len(bits):
            raise ValueError("Table values must be between 1 and the length of bits")
        
    permuted_bits = ""

    for place in table:
        permuted_bits += bits[place - 1]
    return permuted_bits

