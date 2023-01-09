from aes_function import *
from aes_ecb import *
from aes_cbc import *
import sys


print(sys.argv)
if len(sys.argv) > 1:
    if sys.argv[1].lower() == "encrypt":
        if sys.argv[2].lower() == "ecb":
            msg_str = sys.argv[3]
            key_str = sys.argv[4]
            if len(key_str) == 16:
                msg, key = prepare_data_for_encryption_ecb(msg_str, key_str)
                cipheredtext = list_to_string(aes_encrypt128_ecb(msg, key))
                print(cipheredtext)
            elif len(key_str) == 24:
                msg, key = prepare_data_for_encryption_ecb(msg_str, key_str)
                cipheredtext = list_to_string(aes_encrypt192_ecb(msg, key))
                print(cipheredtext)
            elif len(key_str) == 32:
                msg, key = prepare_data_for_encryption_ecb(msg_str, key_str)
                cipheredtext = list_to_string(aes_encrypt256_ecb(msg, key))
                print(cipheredtext)
            else:
                print("Length of key is invalid")
        elif sys.argv[2].lower() == "cbc":
            msg_str = sys.argv[3]
            key_str = sys.argv[4]
            iv_str = sys.argv[5]
            if len(iv_str) != 16:
                print("Length of initialization vector invalid")
            else:
                if len(key_str) == 16:
                    msg, key, iv = prepare_data_for_encryption_cbc(msg_str, key_str, iv_str)
                    cipheredtext = list_to_string(aes_encrypt128_cbc(msg, key, iv))
                    print(cipheredtext)
                elif len(key_str) == 24:
                    msg, key, iv = prepare_data_for_encryption_cbc(msg_str, key_str, iv_str)
                    cipheredtext = list_to_string(aes_encrypt192_cbc(msg, key, iv))
                    print(cipheredtext)
                elif len(key_str) == 32:
                    msg, key, iv = prepare_data_for_encryption_cbc(msg_str, key_str, iv_str)
                    cipheredtext = list_to_string(aes_encrypt256_cbc(msg, key, iv))
                    print(cipheredtext)
                else:
                    print("Length of key is invalid")
        else:
            print("Incorrect input, try again")
    elif sys.argv[1].lower() == "decrypt":
        print("OK")
    else:
        print("Incorrect input, try again")
else:
    type_of_action = input("Do you want to encrypt or decrypt message? ")
    if type_of_action.lower() == "encrypt":
        type_of_encryption = input("Do you want to use ECB or CBC encryption method? ")
        if type_of_encryption.lower() == "ecb":
            msg_str = input("Input message ")
            key_str = input("Input key ")
            if len(key_str) == 16:
                msg, key = prepare_data_for_encryption_ecb(msg_str, key_str)
                cipheredtext = list_to_string(aes_encrypt128_ecb(msg, key))
                print(cipheredtext)
            elif len(key_str) == 24:
                msg, key = prepare_data_for_encryption_ecb(msg_str, key_str)
                cipheredtext = list_to_string(aes_encrypt192_ecb(msg, key))
                print(cipheredtext)
            elif len(key_str) == 32:
                msg, key = prepare_data_for_encryption_ecb(msg_str, key_str)
                cipheredtext = list_to_string(aes_encrypt256_ecb(msg, key))
                print(cipheredtext)
            else:
                print("Length of key is invalid")
        elif type_of_encryption.lower() == "cbc":
            msg_str = input("Input message ")
            key_str = input("Input key ")
            iv_str = input("Input initialization vector ")
            if len(iv_str) != 16:
                print("Length of initialization vector invalid")
            else:
                if len(key_str) == 16:
                    msg, key, iv = prepare_data_for_encryption_cbc(msg_str, key_str, iv_str)
                    cipheredtext = list_to_string(aes_encrypt128_cbc(msg, key, iv))
                    print(cipheredtext)
                elif len(key_str) == 24:
                    msg, key, iv = prepare_data_for_encryption_cbc(msg_str, key_str, iv_str)
                    cipheredtext = list_to_string(aes_encrypt192_cbc(msg, key, iv))
                    print(cipheredtext)
                elif len(key_str) == 32:
                    msg, key, iv = prepare_data_for_encryption_cbc(msg_str, key_str, iv_str)
                    cipheredtext = list_to_string(aes_encrypt256_cbc(msg, key, iv))
                    print(cipheredtext)
                else:
                    print("Length of key is invalid")
        else:
            print("Incorrect input, try again")
    elif type_of_action.lower() == "decrypt":
        print("OK")
    else:
        print("Incorrect input, try again")


