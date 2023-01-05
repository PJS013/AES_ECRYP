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
  for i in range(len(s)//16):
    b = s[i*16: i*16 + 16]
    row = [[], [], [], []]
    for i in range(4):
      for j in range(4):
        row[i].append(b[i + j*4])
    matrix.append(row)
  return matrix