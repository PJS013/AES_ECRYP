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



def aes_decrypt128(ciphertext, key, nr):
    # The key is expanded using the key schedule to generate a sequence of round keys.
    expanded_key = key_expansion128(key)

    # The ciphertext is divided into blocks, and each block is decrypted separately.
    blocks = block_16_bit(ciphertext)

    plaintext = []
    # The decryption of a block begins with the Add Round Key step, where the round key is added to the state using XOR.
    # The state is then transformed through a series of steps, including:
    # - Inverse Shift Rows,
    # - Inverse Sub Bytes
    # - Inverse Mix Columns steps.
    for block in blocks:
        plaintext.append(decrypt_block(block, expanded_key, nr))
    # These steps are designed to undo the operations that were performed during the encryption process.
    # The final state of the last round is the plaintext.
    # print(expanded_key)
    return plaintext

def decrypt_block(block, expanded_key, nr):
     # Initialize the state with the block
    state = block

    # Add the initial round key
    state = add_round_key_decrypt(state, expanded_key[4*nr:])

    # Perform the rounds in reverse order
    for i in range(nr-1, -1, -1):
        print(f"State is {state}")
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key_decrypt(state, expanded_key[4*i:4*(i+1)])
        if i > 0:
            state = inv_mix_columns(state)

    return state

def add_round_key_decrypt(state, round_key):
    # The state is XORed with the round key
    for r in range(4):
        for c in range(4):
            state[r][c] = state[r][c] ^ round_key[r][c]

    return state

def inv_shift_rows(state):
    return [
        [state[0][0], state[3][1], state[2][2], state[1][3]],
        [state[1][0], state[0][1], state[3][2], state[2][3]],
        [state[2][0], state[1][1], state[0][2], state[3][3]],
        [state[3][0], state[2][1], state[1][2], state[0][3]]
    ]

def inv_sub_bytes(state):
    new_state = []
    for r in range(0, 4):
        row = []
        for c in range(0, 4):
            row.append(reverse_lookup(state[r][c]))
        new_state.append(row)
    return new_state

def inv_mix_columns(matrix):
    for c in range(4):
        col = [
            matrix[0][c],
            matrix[1][c],
            matrix[2][c],
            matrix[3][c]
        ]
        col = [
            galois_mult(col[0], 14) ^ galois_mult(col[1], 11) ^ galois_mult(col[2], 13) ^ galois_mult(col[3], 9),
            galois_mult(col[0], 9) ^ galois_mult(col[1], 14) ^ galois_mult(col[2], 11) ^ galois_mult(col[3], 13),
            galois_mult(col[0], 13) ^ galois_mult(col[1], 9) ^ galois_mult(col[2], 14) ^ galois_mult(col[3], 11),
            galois_mult(col[0], 11) ^ galois_mult(col[1], 13) ^ galois_mult(col[2], 9) ^ galois_mult(col[3], 14)]
        matrix[0][c] = col[0]
        matrix[1][c] = col[1]
        matrix[2][c] = col[2]
        matrix[3][c] = col[3]
    return matrix



    # s0 = state[0][0] ^ state[1][0] ^ state[2][0] ^ state[3][0]
    # s1 = state[0][0] ^ state[1][0]
    # s1 ^= s1 * 2 ^ s1 * 4
    # s2 = state[0][0] ^ state[2][0]
    # s2 ^= s2 * 2 ^ s2 * 4
    # s3 = state[0][0] ^ state[3][0]
    # s3 ^= s3 * 2 ^ s3 * 4
    # s4 = state[1][0] ^ state[2][0]
    # s4 ^= s4 * 2 ^ s4 * 4
    # s5 = state[1][0] ^ state[3][0]
    # s5 ^= s5 * 2 ^ s5 * 4
    # s6 = state[2][0] ^ state[3][0]
    # s6 ^= s6 * 2 ^ s6 * 4
    # return [
    #     [
    #         s0 ^ s2 ^ s3 ^ state[0][0] ^ state[1][0] ^ state[2][0] ^ state[3][0],
    #         s1 ^ s4 ^ s6 ^ state[0][0] ^ state[1][0] ^ state[2][0] ^ state[3][0],
    #         s2 ^ s4 ^ s5 ^ state[0][0] ^ state[1][0] ^ state[2][0] ^ state[3][0],
    #         s3 ^ s5 ^ s6 ^ state[0][0] ^ state[1][0] ^ state[2][0] ^ state[3][0]
    #     ],
    #     [
    #         s0 ^ s2 ^ s3 ^ state[0][1] ^ state[1][1] ^ state[2][1] ^ state[3][1],
    #         s1 ^ s4 ^ s6 ^ state[0][1] ^ state[1][1] ^ state[2][1] ^ state[3][1],
    #         s2 ^ s4 ^ s5 ^ state[0][1] ^ state[1][1] ^ state[2][1] ^ state[3][1],
    #         s3 ^ s5 ^ s6 ^ state[0][1] ^ state[1][1] ^ state[2][1] ^ state[3][1]
    #     ],
    #     [
    #         s0 ^ s2 ^ s3 ^ state[0][2] ^ state[1][2] ^ state[2][2] ^ state[3][2],
    #         s1 ^ s4 ^ s6 ^ state[0][2] ^ state[1][2] ^ state[2][2] ^ state[3][2],
    #         s2 ^ s4 ^ s5 ^ state[0][2] ^ state[1][2] ^ state[2][2] ^ state[3][2],
    #         s3 ^ s5 ^ s6 ^ state[0][2] ^ state[1][2] ^ state[2][2] ^ state[3][2]
    #     ],
    #     [
    #         s0 ^ s2 ^ s3 ^ state[0][3] ^ state[1][3] ^ state[2][3] ^ state[3][3],
    #         s1 ^ s4 ^ s6 ^ state[0][3] ^ state[1][3] ^ state[2][3] ^ state[3][3],
    #         s2 ^ s4 ^ s5 ^ state[0][3] ^ state[1][3] ^ state[2][3] ^ state[3][3],
    #         s3 ^ s5 ^ s6 ^ state[0][3] ^ state[1][3] ^ state[2][3] ^ state[3][3]
    #     ]
    # ]

# def aes_decrypt128(ciphertext, key):
#     # The number of rounds to perform
#     nr = 10

#     # The expanded key
#     expanded_key = key_expansion128(key)

#     # Divide the ciphertext into blocks
#     blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

#     # Initialize the plaintext
#     plaintext = b''

#     # Decrypt each block
#     for block in blocks:
#         plaintext += decrypt_block(block, expanded_key, nr)

#     return plaintext

# def decrypt_block(block, expanded_key, nr):
#     # Initialize the state with the block
#     state = block

#     # Add the initial round key
#     state = add_round_key(state, expanded_key[16*nr:])

#     # Perform the rounds in reverse order
#     for i in range(nr-1, -1, -1):
#         state = inv_shift_rows(state)
#         state = inv_sub_bytes(state)
#         state = add_round_key(state, expanded_key[16*i:16*(i+1)])
#         if i > 0:
#             state = inv_mix_columns(state)

#     return state

# def inv_shift_rows(state):
#     # The rows are shifted as follows:
#     # Row 0: no shift
#     # Row 1: shift right by one
#     # Row 2: shift right by two
#     # Row 3: shift right by three
#     return bytearray([
#         state[0],
#         state[13],
#         state[10],
#         state[7],
#         state[4],
#         state[1],
#         state[14],
#         state[11],
#         state[8],
#         state[5],
#         state[2],
#         state[15],
#         state[12],
#         state[9],
#         state[6],
#         state[3],
#     ])

# def inv_sub_bytes(state):
#     return bytearray([reverse_aes_sbox[b] for b in state])

# def add_round_key(state, round_key):
#     # The state is XORed with the round key
#     return bytearray([state[i] ^ round_key[i] for i in range(16)])

# def inv_mix_columns(state):
#     # The inverse mix column operation is a matrix multiplication
#     # of the state matrix and the following matrix:
#     #
#     #   14 11 13  9
#     #   9  14 11 13
#     #   13  9 14 11
#     #   11 13  9 14
#     #
#     # This can be implemented using a series of shifts and XORs
#     s0 = state[0] ^ state[1] ^ state[2] ^ state[3]
#     s1 = state[0] ^ state[1]
#     s1 ^= s1 >> 1 ^ s1 >> 2
#     s2 = state[0] ^ state[2]
#     s2 ^= s2 >> 1 ^ s2 >> 2
#     s3 = state[0] ^ state[3]
#     s3 ^= s3 >> 1 ^ s3 >> 2
#     s4 = state[1] ^ state[2]
#     s4 ^= s4 >> 1 ^ s4 >> 2
#     s5 = state[1] ^ state[3]
#     s5 ^= s5 >> 1 ^ s5 >> 2
#     s6 = state[2] ^ state[3]
#     s6 ^= s6 >> 1 ^ s6 >> 2
#     return bytearray([
#         s0 ^ s2 ^ s3 ^ state[0] ^ state[1] ^ state[2] ^ state[3],
#         s1 ^ s4 ^ s6 ^ state[0] ^ state[1] ^ state[2] ^ state[3],
#         s2 ^ s4 ^ s5 ^ state[0] ^ state[1] ^ state[2] ^ state[3],
#         s3 ^ s5 ^ s6 ^ state[0] ^ state[1] ^ state[2] ^ state[3],
#     ])



# state[0], state[13], state[10], state[7],
# state[4], state[1], state[14], state[11],
# state[8], state[5], state[2], state[15],
# state[12], state[9], state[6], state[3],