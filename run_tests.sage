from sage.all import Integer
import random
import string

load('ascon_sage.sage')
K = '' #key 128 bits
N = '' #nonce 128 bits
A = '' #assoc. data 128 bits
P = '' #plaintext arb. size
T = '' #tag 128 bits
round_constants = [0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b]
rate = 128 #128 bits
IV = 9259414062373011456
P8 = 4
P12 = 0

#generate a random bit string of specified length
def generate_random_bits(length):
    return ''.join(random.choice('01') for _ in range(length))

#generates a key, nonce, and associated data of 128 bits, and a plaintext of random length
def generate_test():
    K = generate_random_bits(128)
    N = generate_random_bits(128)
    A = generate_random_bits(128)
    
    P_length = random.randint(1, 256)
    P = generate_random_bits(P_length)
    
    test_name = f"{P_length}_bit_P"
    
    return test_name, K, N, A, P

def run_test(test_name, K, N, A, P):
    print(f"Test Name: {test_name}")
    try:
        C, T = auth_encrypt(K, N, A, P)
    except Exception as e:
         print ("Failed - encountered error in encrpytion")
         return 1  
    try:
        recoveredP, TP = ver_decryption(K,N,A,C,T)
    except Exception as e:
         print ("Failed - encountered error in decryption")
         return 1
    if P == recoveredP:
        print("Successful encryption and decryption")
        if T == TP:
            print("Decryption verified")
            return 0
    else:
        print("Failed")
    return 1

def main():
    result = 0
    print("Test base testing suite\n","------------------")
    with open("test_parameters.txt", "r") as file:
        for line in file:
            test_name, K, N, A, P = line.strip().split(",")         
            result |= run_test(test_name, K, N, A, P)
            print()
    #test with random tests
    print("Test random variables\n","------------------")
    for i in range(1,51):
        test_name, K, N, A, P = generate_test()
        print("Test",i,":\n","K=",K,'\n',"N=",N,'\n',"A=",A,'\n',"P=",P)
        result |= run_test(test_name, K, N, A, P)
        print()
    if result:
        print("A test has failed")
    else:
        print("Entire test suite has passed\n")
if __name__ == "__main__":
    main()