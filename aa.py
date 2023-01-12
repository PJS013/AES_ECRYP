from aes_function import *
from aes_ecb import *
from aes_cbc import *
from Crypto.Cipher import AES
import binascii
from binascii import unhexlify
import sys

# test 1
original_text = "1122334455667788"
cipheredtext = "59b3fa373d90c66d45b8b12d83922a77"
key = "1122334455667788"
nr = 10
# test 2
# key = "Lorem ipsum dol."
# original_text = "Lorem ipsum dolor sit amet cons."
# cipheredtext = "cabe8d499d598f5b5e0e4aa80765653d2adcb474d7e616f5fa7c4ea0722391df"
# nr = 10
# test 3
# key = "Lorem ipsum dol."
# original_text = "Lorem ipsum dolor sit amet cons.Lorem ipsum dolor sit amet cons."
# cipheredtext = "cabe8d499d598f5b5e0e4aa80765653d2adcb474d7e616f5fa7c4ea0722391dfcabe8d499d598f5b5e0e4aa80765653d2adcb474d7e616f5fa7c4ea0722391df"
# nr = 10

print(cipheredtext)
plaintext = aes_decrypt128_ecb(cipheredtext, key, nr)
print(plaintext)


# j = 0
# for i in range(len(cipheredtext)):
#   if i % 16 == 0:
#     # print(f"{cipheredtext[16*j:16*(j+1)]} ")
#     cipheredtext_matrix.append(cipheredtext[16*j:16*(j+1)])
#     j += 1

# cipheredtext_matrix = []

# _, key = prepare_data_for_encryption_ecb("", key)
# expanded_key = key_expansion128(key)
# plaintext = ""

# NUM_OF_BLOCKS = 0
# for i in range(len(cipheredtext)):
#   if i % 32 == 0:
#     cipheredtext_matrix.append(cipheredtext[16*NUM_OF_BLOCKS:16*(NUM_OF_BLOCKS+1)])
#     NUM_OF_BLOCKS += 1

# k = 2
# for _ in range(NUM_OF_BLOCKS):
#   cipher_matrix = []

#   for i in range(4):
#     row = []
#     for j in range(4):
#       strvalue = cipheredtext[k-2:k]
#       strvalue = f'{strvalue}'
#       strvalue = int(strvalue, 16)
#       # print(k)
#       k += 2
#       row.append(strvalue)
#     cipher_matrix.append(row)

#   # print(cipher_matrix)

#   cipheredtextinhex = cipher_matrix
#   cipheredtextinhex = reverse_matrix(cipheredtextinhex)

# #################################################################
#   round_key = reverse_matrix(expanded_key[-4:])
#   matrix = add_round_key(cipheredtextinhex, round_key)
#   for j in range(1, 10):
#       matrix = inv_shift_rows(matrix)  # shift rows
#       matrix = inv_sub_bytes(matrix)  # substitute bytes
#       round_key = reverse_matrix(expanded_key[-(4*j+4):-(4*j)])
#       matrix = add_round_key(matrix, round_key)  # add round key
#       matrix = inv_mix_columns(matrix)  # mix columns
#   matrix = inv_shift_rows(matrix)  # shift rows
#   matrix = inv_sub_bytes(matrix)  # substitute bytes
#   round_key = reverse_matrix(expanded_key[0:4])
#   matrix = add_round_key(matrix, round_key)
#   message = rewrite_matrix_into_list(matrix)

#   message = [chr(element) for element in message]
#   message = ''.join(message)
#   plaintext += message

# print(plaintext)

# decryptedtext = aes_decrypt128_ecb(cipheredtext, key, 10)
# # print(decryptedtext)
# string = ""
# decryptedtext = decryptedtext[0]
# for row in decryptedtext:
#   for element in row:
#         string += str('{:02x}'.format(int(element)))
# print(string)

# s='59b3fa373d90c66d45b8b12d83922a77'
# matrix = []
# for i in range(len(s) // 16):
#     b = s[i * 16: i * 16 + 16]
#     n=2
#     b = [(b[i:i+n]).strip('') for i in range(0, len(b), n)]
#     # print(f"b {b}")
#     row = [[], [], [], []]
#     for i in range(4):
#         for j in range(2):
#             row[i].append(b[i + j * 4])
#     matrix.append(row)
# print(s)
# print(matrix)

# n=2

# l = [(line[i:i+n]).strip('') for i in range(0, len(line), n)]
# print(l)
# print(cipheredtext)
# print(string_to_hex(string))

# print(len(cipheredtext))


# cipher_text = unhexlify(b'59b3fa373d90c66d45b8b12d83922a77')
# key = b'1122334455667788'


# decrypt_cipher = AES.new(key, AES.MODE_ECB)
# plain_text = decrypt_cipher.decrypt(cipher_text)
# print(plain_text)
# def printhex(num):
#     print(hex(num[0]) + " " + hex(num[1]) + " " + hex(num[2]) + " " + hex(num[3]))

# k = [0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6d, 0x79, 0x20, 0x4b, 0x75, 0x6e, 0x67, 0x20, 0x46, 0x75]
# # print(key_expansion128(k))

# for i in key_expansion128(k):
#      printhex(i)


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

# def printhex(num):
#     print(hex(num[0]) + " " + hex(num[1]) + " " + hex(num[2]) + " " + hex(num[3]))
# message = [
#   [0x87, 0xf2, 0x4d, 0x97],
#   [0xec, 0x6e, 0x4c, 0x90],
#   [0x4a, 0xc3, 0x46, 0xe7],
#   [0x8c, 0xd8, 0x95, 0xa6]
# ]
# for i in inv_sub_bytes(message):
#      printhex(i)


###############################################################################################
# NUM_OF_BLOCKS = 0
# for i in range(len(cipheredtext)):
#   if i % 16 == 0:
#     print(f"{cipheredtext[16*NUM_OF_BLOCKS:16*(NUM_OF_BLOCKS+1)]}")
#     cipheredtext_matrix.append(cipheredtext[16*NUM_OF_BLOCKS:16*(NUM_OF_BLOCKS+1)])
#     NUM_OF_BLOCKS += 1

# # print(cipheredtext.decode("ascii"))
# # key = b'1122334455667788'
# # cipher_text = unhexlify(b'59b3fa373d90c66d45b8b12d83922a77')
# # print(cipher_text)

# # decrypt_cipher = AES.new(key, AES.MODE_ECB)
# # plain_text = decrypt_cipher.decrypt(cipher_text)
# # print(plain_text)
# # print(cipheredtext)
# def getSubStrings(RNA, position):
#     return [RNA[i:i+2] for i in range(position, len(RNA) - 1, 2)]


# for cipher_idx in range(NUM_OF_BLOCKS):
#   cipher = cipheredtext_matrix[cipher_idx]
#   print(f"eloooo {getSubStrings(cipher, 0)}")
#   cipher_matrix = []
#   k = 0
#   for i in range(4):
#     row = []
#     for j in range(4):
#       # print(f"k-2 {k-2}")
#       # print(f"k {k}")
#       strvalue = cipher[k:k+2]

#       print(strvalue)
#       # print(type(strvalue))
#       # strvalue = bytes(strvalue,"utf-8")
#       strvalue = f'{strvalue}'
#       # print(strvalue)
#       # print(int(strvalue, 16))
#       # print(k)
#       strvalue = int(strvalue, 16)
#       # print(hex(strvalue))
#       # row[i] + strvalue
#       # format(strvalue, 'x')
#       k += 2
#       # strvalue = binascii.hexlify(strvalue)
#       row.append(strvalue)
#     # row_new = ', '.join(row)
#     # print(row_new)
#     # row_new = [element.strip("") for element in row_new]
#     cipher_matrix.append(row)
#   print(cipher_matrix)