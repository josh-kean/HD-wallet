from functions import split_I, CKDpriv, CKDpub, N
from basics import parse256
import hmac as h
from mnemonic_phrase import mnemonic
import hashlib

#point(p) returns the x, y pair resulting from multiplication of secp256k1 base poijnt with integer p
    #secp256k1 base point (compressed) is 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
    #secp256k1 base point (uncompressed) is 04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
    #equation is y^2 = x^3 + a*x + b
    #a = 0
    #b = 7
    #order of secp256k1 is  FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
#ser32(i) serializes a 32 bit, unsigned integer as a 4 byte sequence
#ser256(p) serializes the integer p as a 32 byte sequence
#serp(p) serualizes coordinate pair x,y as a byte sequence using (02 or 03)||x depending on if y is + or -
#parse256(p) interprets a 32 byte sequence as a 256 bit number
#chaincode is an additional 32 bytes (256 bits) of entropy applied to both pub and pri keys
#an extended private key is (k, c) where k is the private key and c the chaincode
#an extended pub key is (K, c) where K = point(k) and c the chaincode
#each extended key has 2^31 normal child keys and 2^31 hardened chid keys
#normal keys have an index between 0 and 2^31-1, and hardened keys between 2^31 and 2^32-1


#parent pri key to private child key 'CKDpriv'
#params are kp, cp, index, and result is ki, ci
    #1, check if index > 2^31
        #if yes, I = HMAC_HA512(k = cp, data = 0x00||ser256(kp)||ser32(index))
        #if no, I = HMAC-SHA512(k = cp, data = serp(point(kp))||ser32(index))
    #2 split I into 2 32-byte sequences caled Il and Ir
    #3 ki = parse256(Il)+kp(modn)
    #4 ci = Ir
    #5 check to see if parse256(Il) >= n or if ki == 0. If so, index +=1 and redo function

#public parent key to public child key 'CKDpub'
#params are Kp, cp, index, Ki, ci
    #1 check if index > 2^32
        #if yes, key is hardened and throw an error
        #else, I = HMAC-SHA512(k = cp, data = serp(kp)||ser32(index))
    #2 split I into 2 32-byte sequences Il and Ir
    #3 Ki = point(parse256(Il))+Kp
    #4 ci = Ir
    #chech if parse256(Il) >= n or Ki is point at inf. If yes, index +=1 and redo calc


#private parent key to public child key 'N'
#params are k, c, K, c
    #1 K = point(k)
    #2 c remains unchanges
#To compute do the following
    # for all (hard or not hard) perform CKDpriv(kp, cp), i and then input results as params for N
    # for non hard keys, use kp and cp as input to N and then input results to CKDpub

def mnemonic_gen(phrase=None): #considering returning an iterable object so the binary seed and the word list can be returned from this function
    if phrase:
        main = mnemonic.HashingFunctions(phrase)
        main.create_binary_seed()
        return main.binary_seed
        #import phrase and gen bytecode
    else:
        main = mnemonic.HashingFunctions()
        main.create_master_key()
        return main.binary_seed


def master_key(b_seq):
    b_seq = b_seq.encode('utf-8')
    I = format(int(h.new(b'Bitcoin Seed', msg=b_seq, digestmod=hashlib.sha512).hexdigest(), 16), '1024b')
    print(I)
    iL, iR = split_I(I)
    m_key = parse256(int(iL,16)) #parse256 needsto be input as byte sequence
    c_code = iR
    return [m_key, c_code]

if __name__ == '__main__':
    bseq = mnemonic_gen()
    res = master_key(bseq)
    m_key = res[0]
    c_code = res[1]
    print(f'm_key {m_key}\n\n\n')
    print(f'c_code {c_code}')

