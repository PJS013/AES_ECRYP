from aes_function import *
from aes_tables import *


# def aes_encrypt(plaintext, rounds):
#     # add round key
#     for i in (0, rounds):
#         sub_bytes() # substitute bytes
#         # shift rows
#         # mix columns
#         # add round key
#
# def sub_bytes():


# def printhex(num):
#     print(hex(num[0]) + " " + hex(num[1]) + " " + hex(num[2]) + " " + hex(num[3]))


# key = [0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98]
# round_key = key_expansion(key)
#
# for i in round_key:
#     printhex(i)


# array = [[1,2,3,4],[5,6,7,8],[9,10,11,12],[13,14,15,16]]
# print(array[1][2])
# array = [[0xf2, 0x01, 0xc6, 0xd4], [0x0a, 0x01, 0xc6, 0xd4], [0x22, 0x01, 0xc6, 0xd4], [0x5c, 0x01, 0xc6, 0xd5]]
# array = [[242,1,198,212],[10,1,198,212],[34,1,198,212],[92,1,198,213]]
# mixColumns([0xdb, 0x13, 0x53, 0x45])
# mixColumns([0xf2, 0x0a, 0x22, 0x5c]) # 0x9f 0xdc 0x58 0x9d
# mixColumns([0x01, 0x01, 0x01, 0x01]) # 0x01 0x01 0x01 0x01
# mixColumns([0xc6, 0xc6, 0xc6, 0xc6]) # 0xc6 0xc6 0xc6 0xc6
# mixColumns([0xd4, 0xd4, 0xd4, 0xd5]) # 0xd5 0xd5 0xd7 0xd6
# mixColumns([0x2d, 0x26, 0x31, 0x4c]) # 0x4d 0x7e 0xbd 0xf8
# matrix = mix_columns(array)
# print()

# array = [[0x47, 0x40, 0xa3, 0x4c], [0x37, 0xd4, 0x70, 0x9f], [0x94, 0xe4, 0x3a, 0x42], [0xed, 0xa5, 0xa6, 0xbc]]
# key = [[0xac, 0x19, 0x28, 0x57], [0x77, 0xfa, 0xd1, 0x5c], [0x66, 0xdc, 0x29, 0x00], [0xf3, 0x21, 0x41, 0x6a]]
# for i in range(0,4):
#     print(array[i])
# print()
# add_round_key(array, key)
#
# for i in range(0,4):
#     print(array[i])
