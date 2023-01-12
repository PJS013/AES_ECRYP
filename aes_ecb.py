from aes_function import *
import sys

def ecb_encryption():
    msg_str = sys.argv[3]
    key_str = sys.argv[4]
    if len(key_str) == 16:
        msg, key = prepare_data_for_encryption_ecb(msg_str, key_str)
        cipheredtext = list_to_string(aes_encrypt128_ecb(msg, key))
        print(cipheredtext)
    elif len(key_str) == 24:
        msg, key = prepare_data_for_encryption_ecb(msg_str, key_str)
        cipheredtext = list_to_string(aes_encrypt192_ecb(msg, key))
        print(cipheredtext)
    elif len(key_str) == 32:
        msg, key = prepare_data_for_encryption_ecb(msg_str, key_str)
        cipheredtext = list_to_string(aes_encrypt256_ecb(msg, key))
        print(cipheredtext)
    else:
        print("Length of key is invalid")

def ecb_decryption():
    msg_str = sys.argv[3]
    key_str = sys.argv[4]
    if len(key_str) == 16:
        plaintext = aes_decrypt128_ecb(msg_str, key_str)
        print(plaintext)
    elif len(key_str) == 24:
        plaintext = aes_decrypt192_ecb(msg_str, key_str)
        print(plaintext)
    elif len(key_str) == 32:
        plaintext = aes_decrypt256_ecb(msg_str, key_str)
        print(plaintext)
    else:
        print("Length of key is invalid")

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

# def convert_blocks_elements_to_hex(blocks):
#   for block in blocks:
#     wrap_row = []
#     for small_block in block:
#       row = []
#       for ch in small_block:
#         ch_in_hex = ord(ch)
#         row.append(ch_in_hex)

#       wrap_row.append(row)

#   return [wrap_row]

def prepare_ciphered_matrix(cipheredtext):
    # print(cipheredtext)
    # print(f"len {len(cipheredtext)}")
    cipheredtext_matrix = []
    num_of_blocks = 0
    for i in range(len(cipheredtext)):
        if i % 32 == 0:
            # print(i)
            cipheredtext_matrix.append(cipheredtext[16*num_of_blocks:16*(num_of_blocks+1)])
            num_of_blocks += 1

    # print(f"cipheredtext_matrix - {cipheredtext_matrix}")
    # print(f"num_of_blocks - {num_of_blocks}")
    return cipheredtext_matrix, num_of_blocks

def aes_decrypt128_ecb(cipheredtext, key):
    # The key is expanded using the key schedule to generate a sequence of round keys.
    _, key = prepare_data_for_encryption_ecb("", key)
    expanded_key = key_expansion128(key)
    plaintext = aes_decrypt_ecb(cipheredtext, expanded_key, 10)
    return plaintext

def aes_decrypt192_ecb(cipheredtext, key):
    # The key is expanded using the key schedule to generate a sequence of round keys.
    _, key = prepare_data_for_encryption_ecb("", key)
    expanded_key = key_expansion192(key)
    plaintext = aes_decrypt_ecb(cipheredtext, expanded_key, 12)
    return plaintext

def aes_decrypt256_ecb(cipheredtext, key):
    # The key is expanded using the key schedule to generate a sequence of round keys.
    _, key = prepare_data_for_encryption_ecb("", key)
    expanded_key = key_expansion256(key)
    plaintext = aes_decrypt_ecb(cipheredtext, expanded_key, 14)
    return plaintext

def aes_decrypt_ecb(cipheredtext, expanded_key, nr):

    # The ciphertext is divided into blocks, and each block is decrypted separately.
    cipheredtext_matrix, num_of_blocks = prepare_ciphered_matrix(cipheredtext)

    # The decryption of a block begins with the Add Round Key step, where the round key is added to the state using XOR.
    # The state is then transformed through a series of steps, including:
    # - Inverse Shift Rows,
    # - Inverse Sub Bytes
    # - Inverse Mix Columns steps.
    plaintext = decrypt_block(cipheredtext, num_of_blocks, expanded_key, nr)

    # These steps are designed to undo the operations that were performed during the encryption process.
    # The final state of the last round is the plaintext.
    return plaintext

def decrypt_block(cipheredtext, num_of_blocks, expanded_key, nr):
    k = 2
    plaintext = ""
    for _ in range(num_of_blocks):
        cipher_matrix = []

        for i in range(4):
            row = []
            for j in range(4):
                strvalue = cipheredtext[k-2:k]
                strvalue = f'{strvalue}'
                strvalue = int(strvalue, 16)
                k += 2
                row.append(strvalue)
            cipher_matrix.append(row)

        cipheredtextinhex = cipher_matrix
        cipheredtextinhex = reverse_matrix(cipheredtextinhex)

        round_key = reverse_matrix(expanded_key[-4:])
        matrix = add_round_key(cipheredtextinhex, round_key)
        for j in range(1, nr):
            matrix = inv_shift_rows(matrix)  # shift rows
            matrix = inv_sub_bytes(matrix)  # substitute bytes
            round_key = reverse_matrix(expanded_key[-(4*j+4):-(4*j)])
            matrix = add_round_key(matrix, round_key)  # add round key
            matrix = inv_mix_columns(matrix)  # mix columns
        matrix = inv_shift_rows(matrix)  # shift rows
        matrix = inv_sub_bytes(matrix)  # substitute bytes
        round_key = reverse_matrix(expanded_key[0:4])
        matrix = add_round_key(matrix, round_key)
        message = rewrite_matrix_into_list(matrix)

        message = [chr(element) for element in message]
        message = ''.join(message)
        plaintext += message
        print(message)

    return plaintext


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
