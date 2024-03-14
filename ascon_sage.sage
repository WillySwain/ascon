K = '00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111'#key 128 bits
N = '00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111' #nonce 128 bits
A = '00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111'
P = '00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111'
T = '' #tag 128 bits
round_constants = [0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b]
rate = 128 #128 bits
IV = 9259414062373011456
P8 = 4
P12 = 0

def rotate_right(x, n):
    mask = (1 << 64) - 1 
    return ((x >> n) | (x << (64 - n))) & mask

def bitwise_not(x):
    return 0b1111111111111111111111111111111111111111111111111111111111111111-x

def clear_bits(x, n):
    if n == 0:
        return x
    return x & ~((1 << n) - 1)

def permute(S,round_const_index):
    if round_const_index >= len(round_constants):
        return S
    T = [0] * 5

    S[2] ^^= round_constants[round_const_index] #XOR round constant
    S[0] ^^= S[4]
    S[4] ^^= S[3]
    S[2] ^^= S[1]

    T[0] = S[0] ^^ (bitwise_not(S[1]) & S[2])
    T[1] = S[1] ^^ (bitwise_not(S[2]) & S[3])
    T[2] = S[2] ^^ (bitwise_not(S[3]) & S[4])
    T[3] = S[3] ^^ (bitwise_not(S[4]) & S[0])
    T[4] = S[4] ^^ (bitwise_not(S[0]) & S[1])
    
    T[1] ^^= T[0]
    T[0] ^^= T[4]
    T[3] ^^= T[2]
    T[2] = bitwise_not(T[2])
    S[0] = T[0]^^ rotate_right(T[0],19) ^^ rotate_right(T[0],28)
    S[1] = T[1]^^ rotate_right(T[1],61) ^^ rotate_right(T[1],39)
    S[2] = T[2]^^ rotate_right(T[2],1) ^^ rotate_right(T[2],6)
    S[3] = T[3]^^ rotate_right(T[3],10) ^^ rotate_right(T[3],17)
    S[4] = T[4]^^ rotate_right(T[4],7) ^^ rotate_right(T[4],41)
    
    return permute(S,round_const_index+1)

def auth_encrypt(K,N,A,P):
    C = ''
    S = [0]*5
    K0=int(K[:64],2)
    K1=int(K[64:128],2)
    N0=int(N[:64],2)
    N1=int(N[64:128],2)
    S[0] = IV
    S[1] = K0
    S[2] = K1    
    S[3] = N0
    S[4] = N1
    S=permute(S,P12)
    S[3]^^=K0
    S[4]^^=K1
    #print(bin(S[0]),bin(S[1]),bin(S[2]),bin(S[3]),bin(S[4]))
    A_length = len(A)
    if A_length > 0:
        while A_length >= rate:
            S[0]^^=int(A[:64],2)
            S[1]^^=int(A[64:128],2) 
            
            S = permute(S,P8)
            A=A[rate:]
            A_length-=rate
        if A_length >= 64:
            S[0] ^^= int(A[:64],2)
            S[1] ^^= int(A[64:128],2)
            S[1] ^^= ((0x80) << (56 - 8 * (A_length-8)))
        else:
            if A:
                S[0] ^^= int(A,2) #in case if A=''
            S[0] ^^= ((0x80) << (56 - 8 * (A_length)))
        S=permute(S,P8)
    S[4]^^=1
    P_length = len(P)
    while P_length >= rate:
        S[0] ^^= int(P[:64],2)
        S[1] ^^= int(P[64:128],2)
        #stores
        C+=bin(S[0])[2:].zfill(64)
        C+=bin(S[1])[2:].zfill(64)
        S = permute(S,P8)
        P=P[rate:]
        P_length -= rate
        
    if P_length >= 64:
        S[0] ^^= int(P[:64],2)
        S[1] ^^= int(P[64:128],2)
        C+=bin(S[0])[2:].zfill(64)
        C+=bin(S[1])[2:].zfill(64)
        S[1] ^^= ((0x80) << (56 - 8 * (P_length-8)))
    else:
        if P:
            S[0]^^=int(P,2)
        C+=bin(S[0])[2:].zfill(64)[:P_length]
        S[0] ^^= ((0x80) << (56 - 8 * (P_length)))
    S[2] ^^= K0
    S[3] ^^= K1
    S=permute(S,P12)
    S[3] ^^= K0
    S[4] ^^= K1
    C+=bin(S[3])[2:].zfill(64)[:64]
    C+=bin(S[4])[2:].zfill(64)[:64]
    return C

CT = auth_encrypt(K,N,A,P)
T = CT[-128:]
C = CT[:-128]
print("C is ", C)
print("T is ", T)

def ver_decryption(K, N, A, C, T):
    P=''
    C_length = len(C)  #ABYTES (in bits)
    S = [0]*5
    K0=int(K[:64],2)
    K1=int(K[64:128],2)
    N0=int(N[:64],2)
    N1=int(N[64:128],2)
    S[0] = IV
    S[1] = K0
    S[2] = K1    
    S[3] = N0
    S[4] = N1
    S=permute(S,P12)
    S[3]^^=K0
    S[4]^^=K1
    A_length = len(A)
    if A_length > 0:
        while A_length >= rate:
            S[0]^^=int(A[:64],2)
            S[1]^^=int(A[64:128],2) 
            
            S = permute(S,P8)
            A=A[rate:]
            A_length-=rate
        if A_length >= 64:
            S[0] ^^= int(A[:64],2)
            S[1] ^^= int(A[64:128],2)
            S[1] ^^= ((0x80) << (56 - 8 * (A_length-8)))
        else:
            if A:
                S[0] ^^= int(A,2) #in case if A=''
            S[0] ^^= ((0x80) << (56 - 8 * (A_length)))
        S=permute(S,P8)
    S[4]^^=1
   # print(bin(S[0]),bin(S[1]),bin(S[2]),bin(S[3]),bin(S[4]))
    while C_length >= rate:
        C0 = int(C[:64],2)
        C1 = int(C[64:128],2) 
        P+=bin(S[0]^^C0)[2:].zfill(64)
        P+=bin(S[1]^^C1)[2:].zfill(64)
        S[0]=C0
        S[1]=C1
        S=permute(S,P8)
        C_length-=rate
    if C_length >= 64:
        C0 = int(C[:64],2)
        C1 = int(C[64:C_length],2) #might use in encrypt
        P+=bin(S[0]^^C0)[2:].zfill(64)
        P+=bin(S[1]^^C1)[2:].zfill(C_length-64)
        S[0] = C0
        S[1] = clear_bits(S[1],C_length - 64)
        S[1] |= C1
        S[1] ^^= ((0x80) << (56 - (C_length-64)))
    else:
        if C and C_length>0:
            C0 = int(C[:C_length],2)
        else:
            C0=0
        P+=bin(S[0]^^C0)[2:].zfill(C_length)
        S[0] = clear_bits(S[0],C_length)        
        S[0] |= C0
        S[0] ^^= ((0x80) << (56 - (C_length)))  
    S[2] ^^= K0
    S[3] ^^= K1
    S = permute(S,P12)
    S[3] ^^= K0
    S[4] ^^= K1
    T_prime=''
    T_prime+=bin(S[3])[2:].zfill(64)[:64]
    T_prime+=bin(S[4])[2:].zfill(64)[:64]
    if T_prime != T:
        raise ValueError("T and T* are not equal.")
    return P[:len(C)]

print(ver_decryption(K,N,A,C,T))


