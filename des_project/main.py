from des import encrypt, decrypt

key = "0001001100110100010101110111100110011011101111001101111111110001"

plaintext = "Hello DES!"

ciphertext = encrypt(plaintext, key)
print("Ciphertext:", ciphertext)

decrypted = decrypt(ciphertext, key)
print("Decrypted:", decrypted)