import os

# Basic DES Constants

IP = (
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
)

IP_INV = (
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
)

E = (
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
)

S_BOX = (
    ((14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7), (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8), (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0), (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)),
    ((15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10), (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5), (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15), (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)),
    ((10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8), (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1), (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7), (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)),
    ((7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15), (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9), (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4), (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)),
    ((2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9), (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6), (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14), (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)),
    ((12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11), (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8), (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6), (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)),
    ((4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1), (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6), (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2), (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)),
    ((13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7), (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2), (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8), (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11))
)

P = (
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
)

PC_1 = (
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51,
    43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
)

PC_2 = (
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
)

shifts_table = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

# Bit Conversion and Operation

def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits: list[int]) -> bytes:
    byte_list = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        byte_list.append(byte)
    return bytes(byte_list)

def bits_to_hex(bits: list[int]) -> str:
    hex_str = ""
    for i in range(0, len(bits), 4):
        nibble = 0
        for j in range(4):
            nibble = (nibble << 1) | bits[i + j]
        hex_str += f'{nibble:x}'
    return hex_str

def int_to_bits(n: int, length: int) -> list[int]:
    bits = [0] * length
    for i in range(length - 1, -1, -1):
        bits[i] = n & 1
        n >>= 1
    return bits

def xor_bits(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]

# DES Core Implementation

def permute(block: list[int], table: tuple[int]) -> list[int]:
    return [block[i - 1] for i in table]

def generate_round_keys(key_bits: list[int]) -> list[list[int]]:
    key = permute(key_bits, PC_1)
    C = key[:28]
    D = key[28:]

    round_keys = []
    for shift in shifts_table:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]

        combined_key = C + D
        round_keys.append(permute(combined_key, PC_2))
    return round_keys

def feistel_function(right: list[int], round_key: list[int]) -> list[int]:
    right_expanded = permute(right, E)
    xored = xor_bits(right_expanded, round_key)
    
    sbox_output = []
    for i in range(8):
        chunk = xored[i*6 : (i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        
        val = S_BOX[i][row][col]
        val_bits = int_to_bits(val, 4)
        sbox_output.extend(val_bits)
    
    return permute(sbox_output, P)

def des_process_block(block_bits: list[int], round_keys: list[list[int]]) -> list[int]:
    permuted_block = permute(block_bits, IP)
    left = permuted_block[:32]
    right = permuted_block[32:]

    for i in range(16):
        new_right = xor_bits(left, feistel_function(right, round_keys[i]))
        left = right
        right = new_right

    final_block_data = right + left
    
    return permute(final_block_data, IP_INV)

# CBC and Padding

def add_padding(data: bytes) -> bytes:
    block_size = 8
    padding_len = block_size - (len(data) % block_size)
    padding_byte = bytes([padding_len])
    return data + padding_byte * padding_len

def remove_padding(data: bytes) -> bytes:
    if not data:
        return b""
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 8:
        return data
    return data[:-padding_len]

def des_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padded_plaintext = add_padding(plaintext)
    key_bits = bytes_to_bits(key)
    iv_bits = bytes_to_bits(iv)

    round_keys = generate_round_keys(key_bits)

    ciphertext = b""
    previous_cipher_block = iv_bits

    for i in range(0, len(padded_plaintext), 8):
        block_bytes = padded_plaintext[i:i+8]
        block_bits = bytes_to_bits(block_bytes)
        
        block_to_encrypt = xor_bits(block_bits, previous_cipher_block)
        encrypted_block = des_process_block(block_to_encrypt, round_keys)
        
        ciphertext += bits_to_bytes(encrypted_block)
        previous_cipher_block = encrypted_block
    
    return ciphertext

def des_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    key_bits = bytes_to_bits(key)
    iv_bits = bytes_to_bits(iv)

    round_keys = generate_round_keys(key_bits)
    round_keys.reverse()

    plaintext = b""
    previous_cipher_block = iv_bits

    for i in range(0, len(ciphertext), 8):
        block_bytes = ciphertext[i:i+8]
        block_bits = bytes_to_bits(block_bytes)
        
        decrypted_block_intermediate = des_process_block(block_bits, round_keys)
        plaintext_block = xor_bits(decrypted_block_intermediate, previous_cipher_block)
        
        plaintext += bits_to_bytes(plaintext_block)
        previous_cipher_block = block_bits
    
    return remove_padding(plaintext)

# Main Function

def print_hex(label: str, data: bytes):
    print(f"{label}: {data.hex()}")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    key_str = ""
    iv_str = ""

    clear_screen()
    print("--- DES Enkripsi/Dekripsi ---")
    
    while len(key_str) != 8:
        key_str = input("Masukkan Kunci (8 karakter): ")
        if len(key_str) != 8:
            print("Error: Panjang kunci tidak valid.")
    
    while len(iv_str) != 8:
        iv_str = input("Masukkan IV (8 karakter): ")
        if len(iv_str) != 8:
            print("Error: Panjang IV tidak valid.")

    key_bytes = key_str.encode('latin-1')
    iv_bytes = iv_str.encode('latin-1')

    clear_screen()
    print("--- DES Enkripsi/Dekripsi ---")
    print(f"Kunci: {key_str}")
    print(f"IV: {iv_str}")
    print("\nPilih operasi:")
    print("1. Enkripsi")
    print("2. Dekripsi")
    
    choice = input("Pilihan(1/2): ")

    if choice == '1':
        clear_screen()
        print("--- Enkripsi ---")
        plaintext_str = input("Masukkan Plaintext: ")
        plaintext_bytes = plaintext_str.encode('latin-1')

        ciphertext_bytes = des_encrypt_cbc(plaintext_bytes, key_bytes, iv_bytes)
        
        clear_screen()
        print("--- Hasil Enkripsi ---")
        print(f"Kunci: {key_str}")
        print(f"IV: {iv_str}")
        print(f"Plaintext Original : {plaintext_str}")
        print_hex("Ciphertext (Hex) ", ciphertext_bytes)
        
    elif choice == '2':
        clear_screen()
        print("--- Dekripsi ---")
        hex_ciphertext_str = input("Masukkan Ciphertext (dalam format Hex): ")

        try:
            ciphertext_bytes = bytes.fromhex(hex_ciphertext_str)
            
            decrypted_bytes = des_decrypt_cbc(ciphertext_bytes, key_bytes, iv_bytes)
            decrypted_text = decrypted_bytes.decode('latin-1')

            clear_screen()
            print("--- Hasil Dekripsi ---")
            print(f"Kunci: {key_str}")
            print(f"IV: {iv_str}")
            print_hex("Ciphertext (Hex) ", ciphertext_bytes)
            print(f"Plaintext Didekripsi : {decrypted_text}")

        except (ValueError, TypeError):
            print("Error: Format Hex tidak valid. Pastikan panjangnya genap dan hanya berisi 0-9, a-f.")
        except Exception as e:
            print(f"Error: Gagal dekripsi. Kemungkinan Kunci/IV salah atau data korup. ({e})")
            
    else:
        print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()
