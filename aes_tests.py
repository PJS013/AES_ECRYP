import os

print("In all following encryption tests the message to be encrypted will be the same 32 bit part of lorem ipsum:")
print("Lorem ipsum dolor sit amet cons.")
print("All of the following tests were also executed using python script using Crypto cipher.")
print("Screenshots from the execution of those tests, as well as the structure of used script is available in the report\n")

print("Test #1 - encryption in ecb mode with 16 bit key: Lorem ipsum dol.")
print("Expected outcome: cabe8d499d598f5b5e0e4aa80765653d2adcb474d7e616f5fa7c4ea0722391df")
print("Outcome of the encryption using out code:")
os.system('python main.py encrypt ecb "Lorem ipsum dolor sit amet cons." "Lorem ipsum dol."')
print()

print("Test #2 - encryption in ecb mode with 24 bit key: Lorem ipsum dolor donec.")
print("Expected outcome: 3f72f69eb7f0c07bcbac125c03c835cadc258ae65bfca7d09ff02b7b65e1e268")
print("Outcome of the encryption using out code:")
os.system('python main.py encrypt ecb "Lorem ipsum dolor sit amet cons." "Lorem ipsum dolor donec."')
print()

print("Test #3 - encryption in ecb mode with 32 bit key: Lorem ipsum dolor sit amet cons.")
print("Expected outcome: 12f4f7d7cfe671d954badff41d896fe81aaf91f83e342421c6e7d9c8bbee693f")
print("Outcome of the encryption using out code:")
os.system('python main.py encrypt ecb "Lorem ipsum dolor sit amet cons." "Lorem ipsum dolor sit amet cons."')
print()

print("For the following cbc encryption tests same 16 bit initialization vector was used: Lorem ipsum dol.")
print("Test #4 - encryption in cbc mode with 16 bit key: Lorem ipsum dol.")
print("Expected outcome: 121cc1017c2b473144b9f9d7bfd7cedf09fd4de11baa6247e6554de744ef8bd6")
print("Outcome of the encryption using out code:")
os.system('python main.py encrypt cbc "Lorem ipsum dolor sit amet cons." "Lorem ipsum dol." "Lorem ipsum dol."')
print()

print("Test #5 - encryption in cbc mode with 24 bit key: Lorem ipsum dolor donec.")
print("Expected outcome: 50b1db0899baf667640c7d885aae383b83577b170ab567bf4b0d86c09f1416d9")
print("Outcome of the encryption using out code:")
os.system('python main.py encrypt cbc "Lorem ipsum dolor sit amet cons." "Lorem ipsum dolor donec." "Lorem ipsum dol."')
print()

print("Test #6 - encryption in cbc mode with 32 bit key: Lorem ipsum dolor sit amet cons.")
print("Expected outcome: 3188ed57f22dfb016fef7225dfe3f502755282d3833cc50ef7af0702eaadd1aa")
print("Outcome of the encryption using out code:")
os.system('python main.py encrypt cbc "Lorem ipsum dolor sit amet cons." "Lorem ipsum dolor sit amet cons." "Lorem ipsum dol."')
print()