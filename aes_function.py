def lookup(aes_sbox, byte):
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


def reverse_lookup(reverse_aes_sbox, byte):
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


def shift_rows(array):
    """
    ----------------------------------------------
    Description:
    Parameters:
    Returns:
    ----------------------------------------------
    """
    n = 0
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
            galois_mult(col[0], 2) ^ galois_mult(col[1], 3) ^ galois_mult(col[2], 1) ^ galois_mult(col[3],1),
            galois_mult(col[0], 1) ^ galois_mult(col[1], 2) ^ galois_mult(col[2], 3) ^ galois_mult(col[3],1),
            galois_mult(col[0], 1) ^ galois_mult(col[1], 1) ^ galois_mult(col[2], 2) ^ galois_mult(col[3],3),
            galois_mult(col[0], 3) ^ galois_mult(col[1], 1) ^ galois_mult(col[2], 1) ^ galois_mult(col[3],2)]
        matrix[0][c] = col[0]
        matrix[1][c] = col[1]
        matrix[2][c] = col[2]
        matrix[3][c] = col[3]
    return matrix


def galois_mult(number, galois_multiplier):
    if galois_multiplier == 1:
        return number
    elif galois_multiplier == 2:
        tmp = (number << 1) & 0xff
        return tmp if number < 128 else tmp ^ 0x1b
    elif galois_multiplier == 3:
        return galois_mult(number, 2) ^ number
