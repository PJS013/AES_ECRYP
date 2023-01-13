from aes_function import *
from aes_ecb import *
from aes_cbc import *
from Crypto.Cipher import AES
import binascii
from binascii import unhexlify
import sys

# test 1 ecb 128
# original_text = "1122334455667788"
# cipheredtext = "59b3fa373d90c66d45b8b12d83922a77"
# key = "1122334455667788"
# nr = 10
# # test  ecb 192
# # key = "Lorem ipsum dol."
# # original_text = "Lorem ipsum dolor sit amet cons."
# # cipheredtext = "cabe8d499d598f5b5e0e4aa80765653d2adcb474d7e616f5fa7c4ea0722391df"
# # nr = 10

# # test 3 ecb 256
# # key = "Lorem ipsum dol."
# # original_text = "Lorem ipsum dolor sit amet cons.Lorem ipsum dolor sit amet cons."
# # cipheredtext = "cabe8d499d598f5b5e0e4aa80765653d2adcb474d7e616f5fa7c4ea0722391dfcabe8d499d598f5b5e0e4aa80765653d2adcb474d7e616f5fa7c4ea0722391df"
# # nr = 10

# print(cipheredtext)
# plaintext = aes_decrypt128_ecb(cipheredtext, key, nr)
# print(plaintext)

# test 4 cbc 128
# original_text="Lorem ipsum dolor sit amet cons."
# cipheredtext="121cc1017c2b473144b9f9d7bfd7cedf09fd4de11baa6247e6554de744ef8bd6"
# key="Lorem ipsum dol."
# iv = "Lorem ipsum dol."
# print(original_text)
# _, key, iv = prepare_data_for_encryption_cbc("", key, iv)
# message=aes_decrypt128_cbc(cipheredtext, key, iv)
# print(message)

# test 5 cbc 192
# original_text="Lorem ipsum dolor sit amet cons."
# cipheredtext="50b1db0899baf667640c7d885aae383b83577b170ab567bf4b0d86c09f1416d9"
# key="Lorem ipsum dolor donec."
# iv="Lorem ipsum dol."
# print(original_text)
# _, key, iv = prepare_data_for_encryption_cbc("", key, iv)
# message=aes_decrypt192_cbc(cipheredtext, key, iv)
# print(message)

# test 6 cbc 256
original_text="Lorem ipsum dolor sit amet cons."
cipheredtext="3188ed57f22dfb016fef7225dfe3f502755282d3833cc50ef7af0702eaadd1aa"
key="Lorem ipsum dolor sit amet cons."
iv="Lorem ipsum dol."
print(original_text)
_, key, iv = prepare_data_for_encryption_cbc("", key, iv)
message=aes_decrypt256_cbc(cipheredtext, key, iv)
print(message)
