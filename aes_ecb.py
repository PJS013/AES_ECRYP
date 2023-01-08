from aes_function import *


def aes_encrypt128_ecb(plaintext, key):
    matrices = block_16_bit(plaintext)
    cipheredtext = []
    for i in range(len(matrices)):
        matrix = matrices[i]
        expanded_key = key_expansion128(key)
        # add round key
        round_key = reverse_matrix(expanded_key[0:4])
        add_round_key(matrix, round_key)
        for j in range(1, 10):
            matrix = substitute_bytes(matrix)  # substitute bytes
            matrix = shift_rows(matrix)  # shift rows
            matrix = mix_columns(matrix)  # mix columns
            round_key = reverse_matrix(expanded_key[4*j:4*j+4])
            add_round_key(matrix, round_key)  # add round key
        matrix = substitute_bytes(matrix)  # substitute bytes
        matrix = shift_rows(matrix)  # shift rows
        round_key = reverse_matrix(expanded_key[40:44])
        add_round_key(matrix, round_key)  # add round key
        cipheredtext.extend(rewrite_matrix_into_list(matrix))
    return cipheredtext


def aes_encrypt192_ecb(plaintext, key):
    matrices = block_16_bit(plaintext)
    cipheredtext = []
    for i in range(len(matrices)):
        matrix = matrices[i]
        expanded_key = key_expansion192(key)
        # add round key
        round_key = reverse_matrix(expanded_key[0:4])
        add_round_key(matrix, round_key)
        for j in range(1, 12):
            matrix = substitute_bytes(matrix)  # substitute bytes
            matrix = shift_rows(matrix)  # shift rows
            matrix = mix_columns(matrix)  # mix columns
            round_key = reverse_matrix(expanded_key[4*j:4*j+4])
            add_round_key(matrix, round_key)  # add round key
        matrix = substitute_bytes(matrix)  # substitute bytes
        matrix = shift_rows(matrix)  # shift rows
        round_key = reverse_matrix(expanded_key[48:52])
        add_round_key(matrix, round_key)  # add round key
        cipheredtext.extend(rewrite_matrix_into_list(matrix))
    return cipheredtext


def aes_encrypt256_ecb(plaintext, key):
    matrices = block_16_bit(plaintext)
    cipheredtext = []
    for i in range(len(matrices)):
        matrix = matrices[i]
        expanded_key = key_expansion256(key)
        # add round key
        round_key = reverse_matrix(expanded_key[0:4])
        add_round_key(matrix, round_key)
        for j in range(1, 14):
            matrix = substitute_bytes(matrix)  # substitute bytes
            matrix = shift_rows(matrix)  # shift rows
            matrix = mix_columns(matrix)  # mix columns
            round_key = reverse_matrix(expanded_key[4*j:4*j+4])
            add_round_key(matrix, round_key)  # add round key
        matrix = substitute_bytes(matrix)  # substitute bytes
        matrix = shift_rows(matrix)  # shift rows
        round_key = reverse_matrix(expanded_key[56:60])
        add_round_key(matrix, round_key)  # add round key
        cipheredtext.extend(rewrite_matrix_into_list(matrix))
    return cipheredtext