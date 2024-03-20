from sage.all import Integer
round_constants = [0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b]
rate = 128 #128 bits
IV = 9259414062373011456
P8 = 4
P12 = 0


#rotates number x by n bits to the right
def rotate_right(x, n):
    mask = (1 << 64) - 1 
    return ((x >> n) | (x << (64 - n))) & mask

#bitwise not for 64 bit numbers, Sage not operator (~) does not work as Python's does
def bitwise_not(x):
    return 0b1111111111111111111111111111111111111111111111111111111111111111-x

def getCipherTextBlocks(s):
    
    if(len(s) == 0):
        return
    difference = len(s)%128
    s = s + '0' * (128-difference)
    toRet = 0
    if(len(s)%128):
        toRet = [0] * ceil(len(s)/64 + 2)
    else:
        toRet = [0] * ceil(len(s)/64)
    for i in range(0, ceil(len(s)/64)):
        toRet[i] = int(s[int(0 + 64*i): int(64+64*i)], 2)
    return toRet

#clears out n bits in number x
def clear_bits(x, n):
    if n <= 0:
        return x
    return x & bitwise_not(((1 << n) - 1))

def finalize(F, K0, K1):
    F[2] ^^= K0
    F[3] ^^= K1
    F = permute(F,P12)
    F[3] ^^= K0
    F[4] ^^= K1
    T_prime=''
    T_prime+=bin(F[3])[2:].zfill(64)[:64]
    T_prime+=bin(F[4])[2:].zfill(64)[:64]
    return F, T_prime

def getMessage(c):
    finalString = "";
    for a in c:
        binary_string = bin(a)[2:]
        # Pad the binary string with leading zeros to make it 64 bits long.
        binary_string = binary_string.zfill(64)
        finalString = finalString + binary_string
    return finalString

def appendOneAndMinimumZeros(A):
    difference = (rate-(len(A)%rate))%rate
    extra = int(len(A)%rate)
    numberOfDigits = 0
    if difference == 0:
        numberOfDigits = int(len(A)/64) + 2
        toRet = [0] * (numberOfDigits)
        for i in range(0, numberOfDigits - 2):
            toRet[i] = int(A[64*i:64 + 64*i], 2)
        toRet[numberOfDigits-2] = (1<<63)
        toRet[numberOfDigits-1] = 0
        return toRet, getString(toRet, len(A)+2*64)
    else:
        numberOfDigits = ceil(len(A)/rate)*2
        toRet = [0] * (numberOfDigits)
        for i in range(0, numberOfDigits - 2):
            toRet[i] = int(A[64*i:64 + 64*i], 2)
        if extra >= 64:
            toRet[numberOfDigits-2] = int(A[64*(numberOfDigits-2):64 + 64*(numberOfDigits-2)], 2)
            extra = extra - 64
            if extra > 0:
                toRet[numberOfDigits-1] = (int(A[64 * (numberOfDigits-1):64 * (numberOfDigits-1) + extra], 2) << difference) ^^ (1 << (difference-1))
            else:
                toRet[numberOfDigits-1] = (1<<63)
            return toRet, getString(toRet, len(A)+difference)
        else:
            toRet[numberOfDigits-2] = (int(A[64*(numberOfDigits-2) : 64*(numberOfDigits-2)+extra], 2) << (64-extra)) ^^ (1 << (63-extra))
            return toRet, getString(toRet, len(A)+difference)
            
def getString(arr, numChar):
    if numChar == 0:
        return ""
    toRet = ""
    iter = 0
    numCharCopy = numChar
    while numCharCopy >= 64:
        toRet = toRet + bin(arr[iter])[2:].zfill(64)
        numCharCopy = numCharCopy - 64
        iter = iter + 1
    if numCharCopy > 0:
        toRet = toRet + bin(arr[iter])[2:].zfill(64)[0:numCharCopy]
    return toRet

#recursive permutation function for ascon P12 rounds recurse through entire round_constants array
#while P8 rounds recurse from 0xb4 constant to 0x4b
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

#Authenticated encryption function for ascon128a
#takes key, nonce, associated data, and plaintext
#outputs cipher text C concatenated with tag T 
def auth_encrypt(K,N,A,P):
    #Initilization
    T = ''
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
    #Final initialization XOR
    S[3]^^=K0
    S[4]^^=K1
    #processing associated data
    paddedA, paddedAString = appendOneAndMinimumZeros(A)
    for a in range(0, int(len(paddedA)/2)):
        S[0]^^=paddedA[a*2]
        S[1]^^=paddedA[a*2+1]
        S = permute(S,P8) 
    S[4]^^=1
    #processing plaintext
    paddedP, paddedPString = appendOneAndMinimumZeros(P)
    c = [0] * (len(paddedP))
    for i in range(0, int(len(paddedP)/2)):
        c[i*2] = S[0] ^^ paddedP[i*2]
        c[i*2+1] = S[1] ^^ paddedP[i*2 + 1]
        S[0] = c[i*2]
        S[1] = c[i*2+1]   
        if i != (int(len(paddedP)/2)-1):
            S = permute(S, P8)
    #S[1] ^^= paddedP[-1]
    #c[len(c)-2] = S[0]
    #c[len(c)-1] = S[1]
    #finalization
    S, T = finalize(S, K0, K1)
    return getMessage(c)[0:len(P)], T

#Verified decryption function for ascon128a
#takes key, nonce, associated data, ciphertext, and tag
#outputs plaintext if tags verify, raises error if they do not
def ver_decryption(K, N, A, C, T):
    #initilization
    P = ''
    C_length = len(C)  #ABYTES (in bits)
    SD = [0]*5
    K0=int(K[:64],2)
    K1=int(K[64:128],2)
    N0=int(N[:64],2)
    N1=int(N[64:128],2)
    SD[0] = IV
    SD[1] = K0
    SD[2] = K1    
    SD[3] = N0
    SD[4] = N1
    SD=permute(SD,P12)
    
    #Final initialization XOR
    SD[3]^^=K0
    SD[4]^^=K1
    
    #processing associated data
    paddedA, paddedAString = appendOneAndMinimumZeros(A)
    for a in range(0, int(len(paddedA)/2)):
        SD[0]^^=paddedA[a*2]
        SD[1]^^=paddedA[a*2+1]
        SD = permute(SD,P8) 
    SD[4]^^=1
    
    #processing ciphertext
    paddedC = getCipherTextBlocks(C) 
    p = [0] * (len(paddedC))
    C_len = len(paddedC)

    for r in range(0, C_len/2-1):
        p[r*2] = SD[0] ^^ paddedC[r*2]
        p[r*2+1] = SD[1] ^^ paddedC[r*2 + 1]
        SD[0] = paddedC[r*2]
        SD[1] = paddedC[r*2+1]
        SD = permute(SD, P8)
    p[len(p)-2] = SD[0] ^^ paddedC[len(paddedC)-2]
    p[len(p)-1] = SD[1] ^^ paddedC[len(paddedC)-1]
    newCopy = [0] * 2
    newCopy[0] = p[len(p)-2]
    newCopy[1] = p[len(p)-1]
    Ptw10, _ = appendOneAndMinimumZeros(getString(newCopy, len(C)%rate))
    SD[0] ^^= Ptw10[0]
    SD[1] ^^= Ptw10[1]

    #finalization
    SD, TD = finalize(SD, K0, K1)

    return getMessage(p)[0:len(C)], TD
