from aes_function import *
import sys

def cbc_encryption():
    msg_str = sys.argv[3]
    key_str = sys.argv[4]
    iv_str = sys.argv[5]
    if len(iv_str) != 16:
        print("Length of initialization vector invalid")
    else:
        if len(key_str) == 16:
            msg, key, iv = prepare_data_for_encryption_cbc(msg_str, key_str, iv_str)
            cipheredtext = list_to_string(aes_encrypt128_cbc(msg, key, iv))
            print(cipheredtext)
        elif len(key_str) == 24:
            msg, key, iv = prepare_data_for_encryption_cbc(msg_str, key_str, iv_str)
            cipheredtext = list_to_string(aes_encrypt192_cbc(msg, key, iv))
            print(cipheredtext)
        elif len(key_str) == 32:
            msg, key, iv = prepare_data_for_encryption_cbc(msg_str, key_str, iv_str)
            cipheredtext = list_to_string(aes_encrypt256_cbc(msg, key, iv))
            print(cipheredtext)
        else:
            print("Length of key is invalid")

def cbc_decryption():
    msg_str = sys.argv[3]
    key_str = sys.argv[4]
    iv_str = sys.argv[5]
    if len(iv_str) != 16:
        print("Length of initialization vector invalid")
    else:
        if len(key_str) == 16:
            _, key, iv = prepare_data_for_encryption_cbc("", key_str, iv_str)
            plaintext = aes_decrypt128_cbc(msg_str, key, iv)
            print(plaintext)
        elif len(key_str) == 24:
            pass
        elif len(key_str) == 32:
            pass
        else:
            print("Length of key is invalid")

def aes_encrypt128_cbc(plaintext, key, iv):
    """
    ----------------------------------------------
    Description: this function calls for key expansion function for 128 bit key, then calls for further encryption with
    proper parameters, that is the plaintext, expanded key and integer value 10, as during aes encryption there are ten
    rounds of operations for 128 bit key
    Parameters: plaintext message in form of list of integers, key in form of 4x4 matrix, initial vector iv in form
    of list of integers
    Returns: ciphered message in form of a list of integers
    ----------------------------------------------
    """
    expanded_key = key_expansion128(key)
    cipheredtext = aes_encrypt_cbc(plaintext, expanded_key, iv, 10)
    return cipheredtext


def aes_encrypt192_cbc(plaintext, key, iv):
    """
    ----------------------------------------------
    Description: this function calls for key expansion function for 192 bit key, then calls for further encryption with
    proper parameters, that is the plaintext, expanded key and integer value 12, as during aes encryption there are ten
    rounds of operations for 192 bit key
    Parameters: plaintext message in form of list of integers, key in form of 6x4 matrix, initial vector iv in form
    of list of integers
    Returns: ciphered message in form of a list of integers
    ----------------------------------------------
    """
    expanded_key = key_expansion192(key)
    cipheredtext = aes_encrypt_cbc(plaintext, expanded_key, iv, 12)
    return cipheredtext


def aes_encrypt256_cbc(plaintext, key, iv):
    """
    ----------------------------------------------
    Description: this function calls for key expansion function for 256 bit key, then calls for further encryption with
    proper parameters, that is the plaintext, expanded key and integer value 14, as during aes encryption there are ten
    rounds of operations for 256 bit key
    Parameters: plaintext message in form of list of integers, key in form of 8x4 matrix, initial vector iv in form
    of list of integers
    Returns: ciphered message in form of a list of integers
    ----------------------------------------------
    """
    expanded_key = key_expansion256(key)
    cipheredtext = aes_encrypt_cbc(plaintext, expanded_key, iv, 14)
    return cipheredtext


def aes_encrypt_cbc(plaintext, expanded_key, iv, rounds):
    """
    ----------------------------------------------
    Description:
    Parameters: plaintext message in form of list of integers, expanded_key in form of nx4 matrix,
    where n is 44 for 128 bit key, 52 for 192 bit key and 60 for 256 bit key, and number of rounds, integer,
    10, 12, or 14 for 128 bit, 192 bit, and 256 bit key, respectively
    Returns: ciphered message in form of a list of integers
    ----------------------------------------------
    """
    matrices = block_16_bit(plaintext)
    iv = block_16_bit(iv)
    iv = iv[0]
    cipheredtext = []
    for i in range(len(matrices)):
        matrix = matrices[i]
        add_round_key(matrix, iv)  # initialization vector is XORed with original matrix
        round_key = reverse_matrix(expanded_key[0:4])
        add_round_key(matrix, round_key)
        for j in range(1, rounds):
            matrix = substitute_bytes(matrix)  # substitute bytes
            matrix = shift_rows(matrix)  # shift rows
            matrix = mix_columns(matrix)  # mix columns
            round_key = reverse_matrix(expanded_key[4 * j:4 * j + 4])
            add_round_key(matrix, round_key)  # add round key
        matrix = substitute_bytes(matrix)  # substitute bytes
        matrix = shift_rows(matrix)  # shift rows
        round_key = reverse_matrix(expanded_key[4*rounds:4*rounds+4])
        add_round_key(matrix, round_key)  # add round key
        iv = matrix
        cipheredtext.extend(rewrite_matrix_into_list(matrix))
    return cipheredtext

def aes_decrypt128_cbc(cipheredtext, key, iv):
    expanded_key = key_expansion128(key)
    plaintext = aes_decrypt_cbc(cipheredtext, expanded_key, iv, 10)
    return plaintext

def aes_decrypt192_cbc(cipheredtext, key, iv):
    expanded_key = key_expansion192(key)
    plaintext = aes_decrypt_cbc(cipheredtext, expanded_key, iv, 12)
    return plaintext

def aes_decrypt256_cbc(cipheredtext, key, iv):
    expanded_key = key_expansion256(key)
    plaintext = aes_decrypt_cbc(cipheredtext, expanded_key, iv, 14)
    return plaintext

def aes_decrypt_cbc(cipheredtext, expanded_key, iv, nr):
    # The ciphertext is divided into blocks, and each block is decrypted separately.
    cipheredtext_matrix, num_of_blocks = prepare_ciphered_matrix(cipheredtext)

    # The decryption of a block begins with the Add Round Key step, where the round key is added to the state using XOR.
    # The state is then transformed through a series of steps, including:
    # - Inverse Shift Rows,
    # - Inverse Sub Bytes
    # - Inverse Mix Columns steps.
    plaintext = decrypt_block_cbc(cipheredtext, num_of_blocks, expanded_key, nr, iv)

    # These steps are designed to undo the operations that were performed during the encryption process.
    # The final state of the last round is the plaintext.
    return plaintext

def decrypt_block_cbc(cipheredtext, num_of_blocks, expanded_key, nr, iv):
    """
    Description:
    Parameters:
        (string) cipheredtext - text to decrypt
        (int) num_of_blocks - number of blocks to process
        (string) expanded_key - a key used in decryption process
        (int) nr - number of rounds
    Returns:
    """
    plaintext = ""
    k = 2
    iv = block_16_bit(iv)[0]
    for z in range(num_of_blocks):
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
        iv_next = cipher_matrix
        # # Init round
        cipher_matrix = reverse_matrix(cipher_matrix)
        round_key = reverse_matrix(expanded_key[-4:])
        matrix = add_round_key(cipher_matrix, round_key)

        # Core rounds
        for j in range(1, nr):
            matrix = inv_shift_rows(matrix)  # shift rows
            matrix = inv_sub_bytes(matrix)  # substitute bytes
            round_key = reverse_matrix(expanded_key[-(4*j+4):-(4*j)])
            matrix = add_round_key(matrix, round_key)  # add round key
            matrix = inv_mix_columns(matrix)  # mix columns

        # End round
        matrix = inv_shift_rows(matrix)  # shift rows
        matrix = inv_sub_bytes(matrix)  # substitute bytes
        round_key = reverse_matrix(expanded_key[0:4])
        matrix = add_round_key(matrix, round_key)

        # Adding iv key to XOR the matrix
        matrix = add_round_key(matrix, iv)

        # Post decryption processing
        message = rewrite_matrix_into_list(matrix)
        message = [chr(element) for element in message]
        message = ''.join(message)
        plaintext += message
        iv = iv_next
        iv = reverse_matrix(iv)

    return plaintext