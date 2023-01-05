from aes_function import shift_rows

# def aes_encrypt(plaintext, rounds):
#     # add round key
#     for i in (0, rounds):
#         sub_bytes() # substitute bytes
#         # shift rows
#         # mix columns
#         # add round key
#
# def sub_bytes():



array = [[1,2,3,4],[5,6,7,8],[9,10,11,12],[13,14,15,16]]
rot = shift_rows(array)
for row in rot:
    print(row)

