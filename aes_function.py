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


def shift_rows(array, n=0):
    """
    ----------------------------------------------
    Description:
    Parameters:
    Returns:
    ----------------------------------------------
    """
    # n = 0
    shifted = []
    for row in array:
        row = row[n:] + row[:n]
        n = n + 1
        shifted.append(row)
    return shifted


def mix_columns(matrix):
    """
    ----------------------------------------------
    Description:
    Parameters:
    Returns:
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
    Description:
    Parameters:
    Returns:
    ----------------------------------------------
    """
    if galois_multiplier == 1:
        return number
    elif galois_multiplier == 2:
        tmp = (number << 1) & 0xff
        return tmp if number < 128 else tmp ^ 0x1b
    elif galois_multiplier == 3:
        return galois_mult(number, 2) ^ number


def add_round_key(matrix, round_key):
    """
    ----------------------------------------------
    Description:
    Parameters:
    Returns:
    ----------------------------------------------
    """
    for r in range(4):
        for c in range(4):
            matrix[r][c] = matrix[r][c] ^ round_key[r][c]


def key_expansion128(key):
    """
    ----------------------------------------------
    Description:
    Parameters:
    Returns:
    ----------------------------------------------
    """
    w = []
    for i in range(0, 4):
        w.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])

    for i in range(4, 44):
        temp = w[i-1]
        if i % 4 == 0:
            x = temp[1:] + temp[:1]
            temp = [lookup(val) for val in x]
            rcon = [RC[int(i/4)-1], 0, 0, 0]
            temp = [temp[j] ^ rcon[j] for j in range(0, 4)]
        w.append([w[i-4][j] ^ temp[j] for j in range(0, 4)])
    return w


def key_expansion192(key):
    """
    ----------------------------------------------
    Description:
    Parameters:
    Returns:
    ----------------------------------------------
    """
    w = []
    for i in range(0, 6):
        w.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])

    for i in range(6, 52):
        temp = w[i-1]
        if i % 6 == 0:
            x = temp[1:] + temp[:1]
            temp = [lookup(val) for val in x]
            rcon = [RC[int(i/6)-1], 0, 0, 0]
            temp = [temp[j] ^ rcon[j] for j in range(0, 4)]
        w.append([w[i-6][j] ^ temp[j] for j in range(0, 4)])
    return w


def key_expansion256(key):
    """
    ----------------------------------------------
    Description:
    Parameters:
    Returns:
    ----------------------------------------------
    """
    w = []
    for i in range(0, 8):
        w.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])

    for i in range(8, 60):
        temp = w[i-1]
        if i % 8 == 0:
            x = temp[1:] + temp[:1]
            temp = [lookup(val) for val in x]
            rcon = [RC[int(i/8)-1], 0, 0, 0]
            temp = [temp[j] ^ rcon[j] for j in range(0, 4)]
        elif i % 8 == 4:
            temp = [lookup(val) for val in temp]
        w.append([w[i-8][j] ^ temp[j] for j in range(0, 4)])
    return w


def reverse_matrix(s):
    new_matrix = []
    for i in range(0,4):
        row = []
        for j in range(0,4):
            row.append(s[j][i])
        new_matrix.append(row)
    return new_matrix


def printhex(num):
    print(hex(num[0]) + " " + hex(num[1]) + " " + hex(num[2]) + " " + hex(num[3]))


def rewrite_matrix_into_list(s):
    list = []
    for i in range(0,4):
        for j in range(0,4):
            list.append(s[j][i])
    return list
