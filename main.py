from aes_function import *
from aes_ecb import *
from aes_cbc import *
import sys

# it is possible to run the code from the terminal with, or without extra command lines parameters. If no extra
# parameters is passed, then user is asked to manually input information about operation to be done (encryption
# or decryption, type of encryption (ecb or cbc) as well as parameters necessary for the operation in the console mode
# user can also input data as command lines parameters running program in following manner:
# python main.py [encrypt|decrypt] [ecb|cbc] "plaintext" "key" "initialization vector (if necessary)"

if len(sys.argv) == 5 or len(sys.argv) == 6:
    if sys.argv[1].lower() == "encrypt":
        if sys.argv[2].lower() == "ecb":
            ################
            ecb_encryption()
            ################
        elif sys.argv[2].lower() == "cbc":
            ################
            cbc_encryption()
            ################
        else:
            print("Incorrect input, try again")
    elif sys.argv[1].lower() == "decrypt":
        if sys.argv[2].lower() == "ecb":
            ################
            ecb_decryption()
            ################
        elif sys.argv[2].lower() == "cbc":
            ################
            cbc_decryption()
            ################
    else:
        print("Incorrect input, try again")
elif len(sys.argv) == 1:
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
else:
    print("Incorrect number of parameters")
