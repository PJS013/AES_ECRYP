from aes_function import *
from aes_tables import *


def aes_encrypt(plaintext, rounds, key):
    matrices = block_16_bit(plaintext)
    for i in range(len(matrices)):
        matrix = matrices[i]
        expanded_key = key_expansion128(key)
        # add round key
        round_key = reverse_matrix(expanded_key[0:4])
        add_round_key(matrix, round_key)
        for j in range(1, rounds):
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
        round_key = reverse_matrix(expanded_key[4 * rounds:4 * rounds + 4])
        add_round_key(matrix, round_key)  # add round key
    return matrix