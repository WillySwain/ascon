from sage.all import Integer
load('ascon_sage.sage')
K = '00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111' #key 128 bits
N = '00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111' #nonce 128 bits
A = '00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111' #assoc. data 128 bits
P = '00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111' #plaintext arb. size
T = '' #tag 128 bits
round_constants = [0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b]
rate = 128 #128 bits
IV = 9259414062373011456
P8 = 4
P12 = 0

def run_test(test_name, K, N, A, P):
    print(f"Test Name: {test_name}")
    try:
        ciphertext = auth_encrypt(K, N, A, P)
    except Exception as e:
         print ("Failed - encountered error in encrpytion")
         return
    CT = auth_encrypt(K,N,A,P)
    T = CT[-128:]
    C = CT[:-128]     
    print("C =", C)
    print("T =", T)
    try:
        P= ver_decryption(K,N,A,C,T)
    except Exception as e:
         print ("Failed - encountered error in decryption")
         return
    print("P =", P)
    if P == '-1':
        print("Failed")
    else:
        print("Passed")

def main():
    with open("test_parameters.txt", "r") as file:
        for line in file:
            test_name, K, N, A, P = line.strip().split(",")         
            run_test(test_name, K, N, A, P)
            print()

if __name__ == "__main__":
    main()