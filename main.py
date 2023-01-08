from aes_function import *
from aes_ecb import *
from aes_cbc import *

# working example
# array = [0x54, 0x77, 0x6f, 0x20, 0x4f, 0x6e, 0x65, 0x20, 0x4e, 0x69, 0x6e, 0x65, 0x20, 0x54, 0x77, 0x6f]
# key = [0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6d, 0x79, 0x20, 0x4b, 0x75, 0x6e, 0x67, 0x20, 0x46, 0x75]


key = ['a','f','d','s','a','w','e','f','a','w','f','d','a','w','e','1','a','f','d','s','a','w','e','f','a','w','f','d','a','w','e','1']
array = ['1','3','s','a','s','f','a','f','d','s','a','f',' ','a','w','e','1','3','s','a','s','f','a','f','d','s','a','f',' ','a','w','e']
iv = ['1','3','s','a','s','f','a','f','d','s','a','f',' ','a','w','e']

new_array = []
# new_key = []
# new_iv = []
#
# for i in key:
#     new_key.append(ord(i))

for i in array:
    new_array.append(ord(i))

a = padding(new_array)

# for i in iv:
#     new_iv.append(ord(i))
#
# print(new_key)
# print(new_array)
# print(new_iv)
#

# matrix = aes_encrypt256_cbc(new_array, new_key, new_iv)
for i in a:
    print(hex(i), end=' ')
print()
b = ""
for i in range(len(a)):
    b += str('{:x}'.format(int(a[i])))
print(b)