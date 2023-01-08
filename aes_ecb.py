from aes_function import *
from aes_tables import *


def aes_encrypt128(plaintext, key):
    matrices = block_16_bit(plaintext)
    for i in range(len(matrices)):
        matrix = matrices[i]
        expanded_key = key_expansion128(key)
        # add round key
        round_key = reverse_matrix(expanded_key[0:4])
        add_round_key(matrix, round_key)
        for j in range(1, 10):
            for r in range(4):
                for c in range(4):
                    matrix[r][c] = lookup(matrix[r][c])  # substitute bytes
            matrix = shift_rows(matrix)  # shift rows
            matrix = mix_columns(matrix)  # mix columns
            round_key = reverse_matrix(expanded_key[4*j:4*j+4])
            add_round_key(matrix, round_key)  # add round key
        for r in range(4):
            for c in range(4):
                matrix[r][c] = lookup(matrix[r][c])  # substitute bytes
        matrix = shift_rows(matrix)  # shift rows
        round_key = reverse_matrix(expanded_key[40:44])
        add_round_key(matrix, round_key)  # add round key
    return matrix


def aes_decrypt128(plaintext, key):
    # The number of rounds to perform
    nr = 10

    # The expanded key
    expanded_key = key_expansion128(key)

    # Divide the ciphertext into blocks
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    # Initialize the plaintext
    plaintext = b''

    # Decrypt each block
    for block in blocks:
        plaintext += decrypt_block(block, expanded_key, nr)

    return plaintext

def decrypt_block(block, expanded_key, nr):
    # Initialize the state with the block
    state = block

    # Add the initial round key
    state = add_round_key(state, expanded_key[16*nr:])

    # Perform the rounds in reverse order
    for i in range(nr-1, -1, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, expanded_key[16*i:16*(i+1)])
        if i > 0:
            state = inv_mix_columns(state)

    return state