from aes_function import *


def aes_encrypt128_ecb(plaintext, key):
    """
    ----------------------------------------------
    Description: this function calls for key expansion function for 128 bit key, then calls for further encryption with
    proper parameters, that is the plaintext, expanded key and integer value 10, as during aes encryption there are ten
    rounds of operations for 128 bit key
    Parameters: plaintext message in form of list of integers, key in form of 4x4 matrix
    Returns: ciphered message in form of a list of integers
    ----------------------------------------------
    """
    expanded_key = key_expansion128(key)
    cipheredtext = aes_encrypt_ecb(plaintext, expanded_key, 10)
    return cipheredtext


def aes_encrypt192_ecb(plaintext, key):
    """
    ----------------------------------------------
    Description: this function calls for key expansion function for 192 bit key, then calls for further encryption with
    proper parameters, that is the plaintext, expanded key and integer value 12, as during aes encryption there are ten
    rounds of operations for 192 bit key
    Parameters: plaintext message in form of list of integers, key in form of 6x4 matrix
    Returns: ciphered message in form of a list of integers
    ----------------------------------------------
    """
    expanded_key = key_expansion192(key)
    cipheredtext = aes_encrypt_ecb(plaintext, expanded_key, 12)
    return cipheredtext


def aes_encrypt256_ecb(plaintext, key):
    """
    ----------------------------------------------
    Description: this function calls for key expansion function for 256 bit key, then calls for further encryption with
    proper parameters, that is the plaintext, expanded key and integer value 14, as during aes encryption there are ten
    rounds of operations for 256 bit key
    Parameters: plaintext message in form of list of integers, key in form of 8x4 matrix
    Returns: ciphered message in form of a list of integers
    ----------------------------------------------
    """
    expanded_key = key_expansion256(key)
    cipheredtext = aes_encrypt_ecb(plaintext, expanded_key, 14)
    return cipheredtext


def aes_encrypt_ecb(plaintext, expanded_key, rounds):
    """
    ----------------------------------------------
    Description: function that encrypts a message according to AES pattern of encryption, that is in the first round
    round key is added to the message, stored in 4x4 matrix. Then in rounds <1, number of rounds) substitute_bytes,
    shift_rows, mix_columns and add_round_key operations are done. Last round is similar to previous ones, but columns
    are not mixed there. In this encryption, function block_16_bit breaks message into a number of 4x4 matrices storing
    128 bits of data, thus the encryption is done for each matrix and data from them are stored in cipheredmessage list
    Parameters: plaintext message in form of list of integers, expanded_key in form of nx4 matrix,
    where n is 44 for 128 bit key, 52 for 192 bit key and 60 for 256 bit key, and number of rounds, integer,
    10, 12, or 14 for 128 bit, 192 bit, and 256 bit key, respectively
    Returns: ciphered message in form of a list of integers
    ----------------------------------------------
    """
    matrices = block_16_bit(plaintext)
    cipheredtext = []
    for i in range(len(matrices)):
        matrix = matrices[i]
        round_key = reverse_matrix(expanded_key[0:4])
        matrix = add_round_key(matrix, round_key)
        for j in range(1, rounds):
            matrix = substitute_bytes(matrix)  # substitute bytes
            matrix = shift_rows(matrix)  # shift rows
            # print(type(matrix))
            matrix = mix_columns(matrix)  # mix columns
            round_key = reverse_matrix(expanded_key[4 * j:4 * j + 4])
            matrix = add_round_key(matrix, round_key)  # add round key
        matrix = substitute_bytes(matrix)  # substitute bytes
        matrix = shift_rows(matrix)  # shift rows
        round_key = reverse_matrix(expanded_key[4*rounds:4*rounds+4])
        matrix = add_round_key(matrix, round_key)  # add round key
        cipheredtext.extend(rewrite_matrix_into_list(matrix))
    return cipheredtext

def convert_blocks_elements_to_hex(blocks):
  for block in blocks:
    wrap_row = []
    for small_block in block:
      row = []
      for ch in small_block:
        ch_in_hex = ord(ch)
        row.append(ch_in_hex)

      wrap_row.append(row)

  return [wrap_row]

def aes_decrypt128_ecb(ciphertext, key, nr):
    # The key is expanded using the key schedule to generate a sequence of round keys.
    print(f"Key is {key}")
    expanded_key = key_expansion128_decrypt(key)
    # expanded_key = expanded_key[4:]
    print(f"len of expanded key {len(expanded_key)}")
    # The ciphertext is divided into blocks, and each block is decrypted separately.
    blocks = block_16_bit(ciphertext)
    blocks = convert_blocks_elements_to_hex(blocks)
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
    # print(state)
    # Add the initial round key
    # state = add_round_key_decrypt(state, expanded_key[4*nr:])
    print(f"State after first round {state}")
    print(f"Expanded key {expanded_key}")
    # Perform the rounds in reverse order

    # 10 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-4:])
    state = inv_mix_columns(state)

    # 9 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-8:-4])
    state = inv_mix_columns(state)

    # 8 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-12:-8])
    state = inv_mix_columns(state)

    # 7 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-16:-12])
    state = inv_mix_columns(state)

    # 6 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-20:-16])
    state = inv_mix_columns(state)

    # 5 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-24:-20])
    state = inv_mix_columns(state)

    # 4 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-28:-24])
    state = inv_mix_columns(state)

    # 3 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-32:-28])
    state = inv_mix_columns(state)
    # 59a63d1088f22440df911429a2c818ad
    # 59b3fa373d90c66d45b8b12d83922a77
    # 2 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-36:-32])
    state = inv_mix_columns(state)

    # 1 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-40:-36])
    state = inv_mix_columns(state)

    # 0 round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key_decrypt(state, expanded_key[-44:-40])

    # for i in range(nr-1, -1, -1):
    #     state = inv_shift_rows(state)
    #     state = inv_sub_bytes(state)
    #     print(f"State {i} at {state}")
    #     print(f"Key {i} at {expanded_key[4*i:4*(i+1)]}")
    #     state = add_round_key_decrypt(state, expanded_key[4*i:4*(i+1)])
    #     if i > 0:
    #         state = inv_mix_columns(state)

    return state

def add_round_key_decrypt(state, round_key):
    # The state is XORed with the round key
    for r in range(4):
        for c in range(4):
            # print(f"state[r][c] - {state[r][c]}")
            # print(f"round_key[r][c] - {round_key[r][c]}")
            state[r][c] = state[r][c] ^ round_key[r][c]

    return state


def inv_shift_rows(state):
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][3], state[1][0], state[1][1], state[1][2]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][1], state[3][2], state[3][3], state[3][3]]
    ]

def inv_sub_bytes(state):
    for r in range(0, 4):
        for c in range(0, 4):
            state[r][c]=reverse_lookup((state[r][c]))
    return state

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
            galois_mult(col[0], 11) ^ galois_mult(col[1], 13) ^ galois_mult(col[2], 9) ^ galois_mult(col[3], 14)
        ]
        matrix[0][c] = col[0]
        matrix[1][c] = col[1]
        matrix[2][c] = col[2]
        matrix[3][c] = col[3]
    return matrix
