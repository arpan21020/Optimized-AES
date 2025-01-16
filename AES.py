import numpy as np
import concurrent.futures

class AES:
    # S-box lookup table
    s_box = np.array([
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
    ], dtype=np.uint8)
    
    # Inverse S-box lookup table
    inv_sbox = np.array([
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
], dtype=np.uint8)
    


    
    # Round constants
    r_con = np.array([
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    ], dtype=np.uint8)
    
    
    
    def galois_mul(self,a, b):
        p = 0
        for i in range(8):
            if (b & 1) == 1:
                p ^= a
            hi_bit_set = (a & 0x80)
            a <<= 1
            if hi_bit_set == 0x80:
                a ^= 0x1b 
            b >>= 1
        return p & 0xFF
    def __init__(self):
        # Pre-compute lookup tables for Galois Field multiplication
        self.GF_MUL_2 = np.array([
            self.galois_mul(x, 0x02) for x in range(256)
        ], dtype=np.uint8)
        self.GF_MUL_3 = np.array([
            self.galois_mul(x, 0x03) for x in range(256)
        ], dtype=np.uint8)
        self.GF_MUL_9 = np.array([
            self.galois_mul(x, 0x09) for x in range(256)
        ], dtype=np.uint8)
        self.GF_MUL_11 = np.array([
            self.galois_mul(x, 0x0b) for x in range(256)
        ], dtype=np.uint8)
        self.GF_MUL_13 = np.array([
            self.galois_mul(x, 0x0d) for x in range(256)
        ], dtype=np.uint8)
        self.GF_MUL_14 = np.array([
            self.galois_mul(x, 0x0e) for x in range(256)
        ], dtype=np.uint8)

    def subWord(self,word):
        #Apply S-box substitution to each byte in the word
        for a in range(len(word)):
            row=(word[a]>>4) & 0x0F
            col=word[a] & 0x0F
            word[a]=self.s_box[row][col]
        return word
    def rotWord(self,word):
        return np.roll(word,-1)
    def keyExpansion(self,key,Nk,Nr):
        w = np.zeros((4 * (Nr + 1), 4), dtype=np.uint8)
        i=0
        
        while(i<=Nk-1):
            w[i]=key[4*i:4*i+4]
            i+=1
        # print(np.vectorize(hex)(w))
        while(i<=(4*Nr+3)):
            
            temp=w[i-1].copy()
            # print(np.vectorize(hex)(temp))
            
            if i%Nk==0 :
                temp=self.subWord(self.rotWord(temp))^[self.r_con[i//Nk-1],0,0,0]
            elif(Nk>6 and i%Nk==4):
                temp=self.subWord(temp)
            
            
            w[i]=w[i-Nk]^temp
            # print(np.vectorize(hex)(w))
            
            i+=1
        return w
    
    
    def addRoundKey(self,state,w):
        return state^w
                
                
    
    def subBytes(self,state):
        # Apply S-box substitution to each byte in the state
        rows,cols=state.shape
        for i in range(rows):
            for j in range(cols):
                row=(state[i,j]>>4)& 0xF #0xF=00001111
                col=(state[i,j])& 0xF
                state[i,j]=self.s_box[row][col]
        return state
    
    def shiftRows(self,state):
        # Shift rows of state matrix.
        for row in range(4):
            state[row]=np.roll(state[row],-row)
        return state

    def mixColumns(self,state):
        # Mix columns of state matrix using GF(2^8) arithmetic.
        result = np.zeros_like(state)
        for i in range(4):
            col = state[:, i]
            result[0, i] = self.GF_MUL_2[col[0]] ^ self.GF_MUL_3[col[1]] ^ col[2] ^ col[3]
            result[1, i] = col[0] ^ self.GF_MUL_2[col[1]] ^ self.GF_MUL_3[col[2]] ^ col[3]
            result[2, i] = col[0] ^ col[1] ^ self.GF_MUL_2[col[2]] ^ self.GF_MUL_3[col[3]]
            result[3, i] = self.GF_MUL_3[col[0]] ^ col[1] ^ col[2] ^ self.GF_MUL_2[col[3]]
        return result
    
    
    def cipher(self,input,Nr,w):
        # Main cipher function.
        state=input.reshape(4,4)
        
        state=self.addRoundKey(state,w[0:4]).T
        # print("state block after roundKey:", np.vectorize(hex)(state))
        for round in range(1,Nr):
            # print("------------Round :",round,"------------")
            state=self.subBytes(state)
            # print("state block after subByte:", np.vectorize(hex)(state))
        
            state=self.shiftRows(state)
            # print("state block after shiftRows:", np.vectorize(hex)(state))
            
            state=self.mixColumns(state)
            # print("state block after mixColumns:", np.vectorize(hex)(state))
            
            state=self.addRoundKey(state,w[4*round:4*round+4].T)
            # print("key:",np.vectorize(hex)(w[4*round:4*round+4].T))
            # print("state block after roundKey again:", np.vectorize(hex)(state))
            
            
        # print("==========================================")
        state=self.subBytes(state)
        # print("state block after subBytes:", np.vectorize(hex)(state))
        
        state=self.shiftRows(state)
        # print("state block after shiftRows:", np.vectorize(hex)(state))
        
        state=self.addRoundKey(state,w[4*Nr:4*Nr+4].T)
        # print("state block after round:", np.vectorize(hex)(state))
        
        return state
    
    def invShiftRows(self,state):
        for row in range(4):
            state[row]=np.roll(state[row],row)
        return state
    
    def invSubBytes(self,state):
        rows,cols=state.shape
        for i in range(rows):
            for j in range(cols):
                row=(state[i,j]>>4)& 0xF #0xF=00001111
                col=(state[i,j])& 0xF
                state[i,j]=self.inv_sbox[row][col]
        return state
    
    def invMixColumns(self,state):
        result = np.zeros_like(state)
        for i in range(4):
            col = state[:, i]
            result[0, i] = self.GF_MUL_14[col[0]] ^ self.GF_MUL_11[col[1]] ^ self.GF_MUL_13[col[2]] ^ self.GF_MUL_9[col[3]]
            result[1, i] = self.GF_MUL_9[col[0]] ^ self.GF_MUL_14[col[1]] ^ self.GF_MUL_11[col[2]] ^ self.GF_MUL_13[col[3]]
            result[2, i] = self.GF_MUL_13[col[0]] ^ self.GF_MUL_9[col[1]] ^ self.GF_MUL_14[col[2]] ^ self.GF_MUL_11[col[3]]
            result[3, i] = self.GF_MUL_11[col[0]] ^ self.GF_MUL_13[col[1]] ^ self.GF_MUL_9[col[2]] ^ self.GF_MUL_14[col[3]]
        return result
    
    def invCipher(self,input,Nr,w):
        state=input.reshape(4,4)
        # print(state)
        state=self.addRoundKey(state,w[4*Nr:4*Nr+4].reshape(4,4))
        
        for round in range(Nr-1,0,-1):
            state=self.invShiftRows(state)
            state=self.invSubBytes(state)
            state=self.addRoundKey(state,w[4*round:4*round+4].reshape(4,4))
            state=self.invMixColumns(state)
        state=self.invShiftRows(state)
        state=self.invSubBytes(state)
        state=self.addRoundKey(state,w[0:4].reshape(4,4))
        return state

def string_to_bytes(input_string):
    """Convert a 16-byte string to numpy array of bytes."""
    if len(input_string) != 16:
        raise ValueError("Input string must be exactly 16 bytes long")
    return np.array([ord(c) for c in input_string], dtype=np.uint8)

def bytes_to_string(byte_array):
    """Convert numpy array of bytes back to string."""
    return ''.join(chr(b) for b in byte_array)

def process_block(aes, block, Nr, expanded_key): 
    return aes.cipher(block, Nr, expanded_key)
def main():
    Nk = 4  # Key length in 32-bit words
    Nr = 10  # Number of rounds
    
    
     # Sample 16-byte key string
    # key_string = "MySecretKey12345"  # Exactly 16 bytes
    # Sample 16-byte input string
    # input_strings = ["Hello, AES-128!!", "Encrypt this tex", "Another 16 bytes"] # Exactly 16 bytes each 
    # Convert strings to byte arrays 
    # key = string_to_bytes(key_string) 
    # input_blocks = [string_to_bytes(s) for s in input_strings]
    
    aes128=AES()
    key = np.array([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ], dtype=np.uint8)
    # Expand the key
    input_block = np.array([
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    ], dtype=np.uint8)
    expanded_key = aes128.keyExpansion(key, Nk, Nr)
    # print("ExpandedKey:")
    # print(np.vectorize(hex)(expanded_key))

    
   # Using a thread pool to process multiple blocks 
    # with concurrent.futures.ThreadPoolExecutor() as executor: 
    #    futures = [executor.submit(process_block, aes128, block, Nr, expanded_key) for block in input_blocks] 
    #    encrypted_blocks = [future.result() for future in concurrent.futures.as_completed(futures)] 
    # for i, block in enumerate(encrypted_blocks): 
    #     print(f"Input block {i+1}:", input_blocks[i]) 
    #     print(f"Encrypted block {i+1}:", block.flatten())
    
    # # Encrypt the block
    encrypted_block = aes128.cipher(input_block, Nr, expanded_key)
    decrypted_block=aes128.invCipher(encrypted_block,Nr,expanded_key)
    print("Input block:", np.vectorize(hex)(input_block))
    print("Encrypted block:", np.vectorize(hex)(encrypted_block))
    # print("Encrypted block:", decrypted_block.flatten())

main()