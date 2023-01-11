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
    # n=2
    # ciphertext = [int(ciphertext[i:i+n]) for i in range(0, len(ciphertext), n)]
    print(f"begining {ciphertext}")
    _, key = prepare_data_for_encryption_ecb("", key)
    expanded_key = key_expansion128(key)
    # expanded_key = expanded_key[4:]
    # The ciphertext is divided into blocks, and each block is decrypted separately.
    blocks = block_16_bit(ciphertext)
    # print(blocks)
    # blocks = convert_blocks_elements_to_hex(blocks)
    # print(blocks)

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

def decrypt_block(matrix, expanded_key, nr):
     # Initialize the state with the block
    # print(state)
    # Add the initial round key
    # state = add_round_key_decrypt(state, expanded_key[4*nr:])
    # print(f"State after first round {state}")
    # print(f"Expanded key {expanded_key}")
    # Perform the rounds in reverse order
    matrix = add_round_key(matrix, reverse_matrix(expanded_key[-4:]))

    for i in range(nr-1, 0, -1):
        matrix = inv_shift_rows(matrix)
        matrix = inv_sub_bytes(matrix)
        matrix = add_round_key(matrix, reverse_matrix(expanded_key[4*i:4*(i+1)]))
        matrix = inv_mix_columns(matrix)

    matrix = inv_shift_rows(matrix)
    matrix = inv_sub_bytes(matrix)
    matrix = add_round_key(matrix, reverse_matrix(expanded_key[:4]))
    return matrix



def inv_shift_rows(matrix):
    return [
        [matrix[0][0], matrix[0][1], matrix[0][2], matrix[0][3]],
        [matrix[1][3], matrix[1][0], matrix[1][1], matrix[1][2]],
        [matrix[2][2], matrix[2][3], matrix[2][0], matrix[2][1]],
        [matrix[3][1], matrix[3][2], matrix[3][3], matrix[3][0]]
    ]

def inv_sub_bytes(matrix):
    for r in range(0, 4):
        for c in range(0, 4):
            matrix[r][c]=reverse_lookup((matrix[r][c]))
    return matrix

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
