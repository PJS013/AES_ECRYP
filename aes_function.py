from aes_tables import *


def lookup(byte):
    """
  ----------------------------------------------
  Description:
  Parameters:
  Returns:
  ----------------------------------------------
  """
    x = byte >> 4
    y = byte & 15
    return aes_sbox[x][y]


def reverse_lookup(byte):
    """
  ----------------------------------------------
  Description:
  Parameters:
  Returns:
  ----------------------------------------------
  """
    x = byte >> 4
    y = byte & 15
    return reverse_aes_sbox[x][y]


def substitute_bytes(matrix):
    """
    ----------------------------------------------
    Description: in this function we iterate over the matrix from the input calling lookup function on its values
    and assigning them to the appropriate cell in the matrix
    Parameters: 4x4 matrix with integers
    Returns: 4x4 matrix filled with integers from sbox
    ----------------------------------------------
    """
    for r in range(4):
        for c in range(4):
            matrix[r][c] = lookup(matrix[r][c])
    return matrix


def block_16_bit(s):
    """
    ----------------------------------------------
    Description:
    Parameters:
    Returns:
    ----------------------------------------------
    """
    matrix = []
    for i in range(len(s) // 16):
        b = s[i * 16: i * 16 + 16]
        row = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                row[i].append(b[i + j * 4])
        matrix.append(row)
    return matrix


def shift_rows(matrix):
    """
    ----------------------------------------------
    Description: this function shifts numbers in each
    row n positions to the left, starting from n = 0 for the first
    row and incrementing it
    Parameters: 4x4 matrix with integers
    Returns: 4x4 matrix with shifted values
    ----------------------------------------------
    """
    n = 0
    shifted = []
    for row in matrix:
        row = row[n:] + row[:n]
        n += 1
        shifted.append(row)
    return shifted


def mix_columns(matrix):
    """
    ----------------------------------------------
    Description: In AES column mixing is done by multiplication of columns of matrix with message getting encrypted,
    or decrypted with other specified matrix in GF(2^8).
    Parameters: 4x4 matrix with integer values
    Returns: 4x4 matrix with mixed integer values
    ----------------------------------------------
    """
    for c in range(4):
        col = [
            matrix[0][c],
            matrix[1][c],
            matrix[2][c],
            matrix[3][c]
        ]
        col = [
            galois_mult(col[0], 2) ^ galois_mult(col[1], 3) ^ galois_mult(col[2], 1) ^ galois_mult(col[3], 1),
            galois_mult(col[0], 1) ^ galois_mult(col[1], 2) ^ galois_mult(col[2], 3) ^ galois_mult(col[3], 1),
            galois_mult(col[0], 1) ^ galois_mult(col[1], 1) ^ galois_mult(col[2], 2) ^ galois_mult(col[3], 3),
            galois_mult(col[0], 3) ^ galois_mult(col[1], 1) ^ galois_mult(col[2], 1) ^ galois_mult(col[3], 2)]
        matrix[0][c] = col[0]
        matrix[1][c] = col[1]
        matrix[2][c] = col[2]
        matrix[3][c] = col[3]
    return matrix


def galois_mult(number, galois_multiplier):
    """
    ----------------------------------------------
    Description: Multiplication in GF(2^8) by one is simply the same number, multiplication by two is equivalent to
    shifting the number left by one, and XORing the value by 0x1B if the highest bit is one. Multiplication by three is
    done by multiplying the number by two and then XORing it with original value again
    Parameters: Integer number to be multiplied and galois_multiplier, that is constant that is used for multiplication
    Returns: Integer number that is the result of multiplication
    ----------------------------------------------
    """
    if galois_multiplier == 1:
        return number
    elif galois_multiplier == 2:
        tmp = (number << 1) & 0xff
        return tmp if number < 128 else tmp ^ 0x1b
    elif galois_multiplier == 3:
        return galois_mult(number, 2) ^ number
    elif galois_multiplier == 9:
        return galois_mult(((number, 2), 2), 2) ^ number
    elif galois_multiplier == 11:
        return galois_mult(galois_mult(galois_mult(number, 2), 2) ^ number, 2) ^ number
    elif galois_multiplier == 13:
        return galois_mult(galois_mult(galois_mult(number, 2) ^ number, 2), 2) ^ number
    elif galois_multiplier == 14:
        return galois_mult(galois_mult(galois_mult(number, 2) ^ number, 2) ^ number, 2)


def add_round_key(matrix, round_key):
    """
    ----------------------------------------------
    Description: function XORing two 4x4 matrices of integers
    Parameters: two 4x4 matrices of integers
    Returns: 4x4 matrix with XORed values
    ----------------------------------------------
    """
    for r in range(4):
        for c in range(4):
            matrix[r][c] = matrix[r][c] ^ round_key[r][c]
    return matrix


def key_expansion128(key):
    """
    ----------------------------------------------
    Description: AES uses a key schedule to expand shorter key into a number of separate round keys. In case of 128 bit
    key, expanded key starts with 4 32 bit words taken from original key, then next words are created by XORing
    the fourth previous word with the first previous word, except for every fourth word, where the first previous word
    that is to be XORed by the fourth previous word is first shifted by one byte to the left in the circular manner,
    substituted with values from the s-box and xored with a round constant
    Parameters: 128 bit key in form of a list
    Returns: matrix containing 44 32 bit word that will be used as round keys in encryption process
    ----------------------------------------------
    """
    w = []
    for i in range(0, 4):
        w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            x = temp[1:] + temp[:1]
            temp = [lookup(val) for val in x]
            rcon = [RC[int(i / 4) - 1], 0, 0, 0]
            temp = [temp[j] ^ rcon[j] for j in range(0, 4)]
        w.append([w[i - 4][j] ^ temp[j] for j in range(0, 4)])
    return w


def key_expansion192(key):
    """
    ----------------------------------------------
    Description: AES uses a key schedule to expand shorter key into a number of separate round keys. In case of 192 bit
    key, expanded key starts with 6 32 bit words taken from original key, then next words are created by XORing
    the sixth previous word with the first previous word, except for every sixth word, where the first previous word
    that is to be XORed by the sixth previous word is first shifted by one byte to the left in the circular manner,
    substituted with values from the s-box and XORed with a round constant
    Parameters: 192 bit key in form of a list
    Returns: matrix containing 52 32 bit word that will be used as round keys in encryption process
    ----------------------------------------------
    """
    w = []
    for i in range(0, 6):
        w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    for i in range(6, 52):
        temp = w[i - 1]
        if i % 6 == 0:
            x = temp[1:] + temp[:1]
            temp = [lookup(val) for val in x]
            rcon = [RC[int(i / 6) - 1], 0, 0, 0]
            temp = [temp[j] ^ rcon[j] for j in range(0, 4)]
        w.append([w[i - 6][j] ^ temp[j] for j in range(0, 4)])
    return w


def key_expansion256(key):
    """
    ----------------------------------------------
    Description: AES uses a key schedule to expand shorter key into a number of separate round keys. In case of 256 bit
    key, expanded key starts with 8 32 bit words taken from original key, then next words are created by XORing
    the eight previous word with the first previous word, except for every eight word, where the first previous word
    that is to be XORed by the eight previous word is first shifted by one byte to the left in the circular manner,
    substituted with values from the s-box and XORed with a round constant. If the position of the word is a multiple
    of four, then the first previous word that is to be XORed by the eight previous word is substituted with values
    from the s-box
    Parameters: 256 bit key in form of a list
    Returns: matrix containing 60 32 bit word that will be used as round keys in encryption process
    ----------------------------------------------
    """
    w = []
    for i in range(0, 8):
        w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            x = temp[1:] + temp[:1]
            temp = [lookup(val) for val in x]
            rcon = [RC[int(i / 8) - 1], 0, 0, 0]
            temp = [temp[j] ^ rcon[j] for j in range(0, 4)]
        elif i % 8 == 4:
            temp = [lookup(val) for val in temp]
        w.append([w[i - 8][j] ^ temp[j] for j in range(0, 4)])
    return w


def reverse_matrix(s):
    """
    ----------------------------------------------
    Description: Helper function used to reverse matrix in a form that values at place [1][0] is saved to the place
    [0][1], value at place [2][1] is saved at place [1][2] and so on
    Parameters: 4x4 matrix of integers
    Returns: 4x4 matrix of integers
    ----------------------------------------------
    """
    new_matrix = []
    for i in range(0, 4):
        row = []
        for j in range(0, 4):
            row.append(s[j][i])
        new_matrix.append(row)
    return new_matrix


def rewrite_matrix_into_list(s):
    """
    ----------------------------------------------
    Description: Helper function used to write data from 4x4 matrix in form of a list
    Parameters: 4x4 matrix
    Returns: List of values
    ----------------------------------------------
    """
    list = []
    for i in range(0, 4):
        for j in range(0, 4):
            list.append(s[j][i])
    return list


def padding(message):
    """
    ----------------------------------------------
    Description: ISO padding method is one of the methods used to extend the message to be encrypted, if the message is
    too short, that is its length is not a multiple of 128 bit. In this method the message is appended with value 0x80
    followed by as many zeroes as neeeded to fill the last block
    Parameters: Message in form of a list of integer values
    Returns: Padded message in form of a list of integer values
    ----------------------------------------------
    """
    if len(message) % 16 != 0:
        message.append(0x80)
    while len(message) % 16 != 0:
        message.append(0)
    return message


def prepare_data_for_encryption_ecb(msg_str, key_str):
    """
    ----------------------------------------------
    Description: Helper function used to prepare data passed by user for encryption. User passes data in form of string
    of characters and this function saves them in form of list of integers
    Parameters: two strings of characters, that is message to be encrypted and encryption key
    Returns: two lists of integers, that is message to be encrypted and encryption key
    ----------------------------------------------
    """
    msg = [ord(list(msg_str)[i]) for i in range(len(msg_str))]
    msg = padding(msg)
    key = [ord(list(key_str)[i]) for i in range(len(key_str))]
    return msg, key


def prepare_data_for_encryption_cbc(msg_str, key_str, iv_str):
    """
    ----------------------------------------------
    Description: Helper function used to prepare data passed by user for encryption. User passes data in form of string
    of characters and this function saves them in form of list of integers
    Parameters: three strings of characters, that is message to be encrypted, encryption key and initialization vector
    Returns: three lists of integers, that is message to be encrypted, encryption key and initialization vector
    ----------------------------------------------
    """
    msg = [ord(list(msg_str)[i]) for i in range(len(msg_str))]
    msg = padding(msg)
    key = [ord(list(key_str)[i]) for i in range(len(key_str))]
    iv = [ord(list(iv_str)[i]) for i in range(len(iv_str))]
    return msg, key, iv


def list_to_string(list):
    """
    ----------------------------------------------
    Description: Helper function used to write data from list filled with integers into string of hexadecimal values,
    without the 0x prefix
    Parameters: List of integers
    Returns: String composed of hexadecimal values
    ----------------------------------------------
    """
    string = ""
    for i in range(len(list)):
        string += str('{:02x}'.format(int(list[i])))
    return string