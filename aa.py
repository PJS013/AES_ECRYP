from aes_function import *
from aes_ecb import *
from aes_cbc import *
from Crypto.Cipher import AES
from binascii import unhexlify
import sys

original_text = "1122334455667788"
cipheredtext = "59b3fa373d90c66d45b8b12d83922a77"
key = "1122334455667788"

decryptedtext = aes_decrypt128_ecb(cipheredtext, key, 10)
print(decryptedtext)
string = ""
decryptedtext = decryptedtext[0]
for row in decryptedtext:
  for element in row:
        string += str('{:02x}'.format(int(element)))
print(string)

# print(cipheredtext)
# print(string_to_hex(cipheredtext))

# print(len(cipheredtext))


cipher_text = unhexlify(b'59b3fa373d90c66d45b8b12d83922a77')
key = b'1122334455667788'


decrypt_cipher = AES.new(key, AES.MODE_ECB)
plain_text = decrypt_cipher.decrypt(cipher_text)
print(plain_text)


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


